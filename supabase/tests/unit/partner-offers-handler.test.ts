// supabase/tests/unit/partner-offers-handler.test.ts
//
// The `offers-admin` handler and its strict shapes (docs/security/partner-auth-design.md 12, 30; AT(14); slice S6, the Edge half of 0059), against an in-memory `PartnerDb`. Eligibility is validated with
// the Edge-local AT(14) schema gate (offer-eligibility.ts) before any port is opened.

import { describe, expect, it } from "vitest";
import {
  handlePartnerOffersAdminRequest,
  OFFERS_BUCKET,
  OFFERS_PER_MEMBER_PER_HOUR,
  type PartnerOffersAdminDeps,
} from "../../functions/_shared/partner/offers-handler.ts";
import {
  type OfferAdminRow,
  type OfferApproveStatus,
  type OfferEndStatus,
  type OfferUpsertResult,
  type PartnerDb,
  type PartnerOffersAdminTx,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
} from "../../functions/_shared/partner/ports.ts";
import { fnReq, ORIGIN, SESSION_TOKEN, sha256Hex } from "./partner-fakes.ts";

const FN = "offers-admin";
const ID = "00000000-0000-4000-8000-0000000000aa";
/** A catalog-shaped course id (crs_ + 26 Crockford chars) so RuleExprSchema accepts it. */
const COURSE_ID = "crs_01H0ABCDEFGHJKMNPQRSTVWXYZ";
const ELIGIBLE = {
  kind: "compare",
  op: ">=",
  left: { kind: "agg", name: "played", courseId: COURSE_ID },
  right: { kind: "literal", value: 1 },
};
const OFFER_BODY = {
  trailId: "trl_t",
  facilityId: "fac_x",
  eligibility: ELIGIBLE,
  funder: "operator",
  budgetCap: 100,
  faceValue: 10,
  validFrom: "2030-01-01",
  validTo: "2030-12-31",
};

interface World {
  calls: string[];
  committed: boolean[];
  rolledBack: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  rows: OfferAdminRow[];
  upsert: OfferUpsertResult;
  approve: OfferApproveStatus;
  end: OfferEndStatus;
  throwIn: string | null;
  throwWith: Error;
  rateOk: boolean;
  bindRefused: boolean;
}

function world(): { w: World; deps: PartnerOffersAdminDeps } {
  const w: World = {
    calls: [],
    committed: [],
    rolledBack: [],
    rate: [],
    rows: [{
      id: ID,
      termsId: null,
      trailId: "trl_t",
      facilityId: "fac_x",
      eligibility: ELIGIBLE,
      funder: "operator",
      sponsorshipId: null,
      budgetCap: 100,
      budgetUsed: 0,
      budgetReserved: 0,
      maxRedemptions: null,
      faceValue: 10,
      validFrom: "2030-01-01",
      validTo: "2030-12-31",
      status: "draft",
    }],
    upsert: { status: "ok", id: ID },
    approve: "ok",
    end: "ok",
    throwIn: null,
    throwWith: new PartnerAuthorityRefused(),
    rateOk: true,
    bindRefused: false,
  };
  const tx: PartnerOffersAdminTx = {
    async listOffers(trailId) {
      w.calls.push("tx.listOffers");
      if (w.throwIn === "listOffers") throw w.throwWith;
      return w.rows.map((r) => ({ ...r, trailId }));
    },
    async upsertOffer(...args) {
      w.calls.push("tx.upsertOffer");
      w.calls.push(`args:${JSON.stringify(args.slice(0, 3))}`);
      if (w.throwIn === "upsertOffer") throw w.throwWith;
      return w.upsert;
    },
    async approveOffer(id) {
      w.calls.push("tx.approveOffer");
      w.calls.push(`id:${id}`);
      if (w.throwIn === "approveOffer") throw w.throwWith;
      return w.approve;
    },
    async endOffer(id) {
      w.calls.push("tx.endOffer");
      w.calls.push(`id:${id}`);
      if (w.throwIn === "endOffer") throw w.throwWith;
      return w.end;
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
    withSponsorships: reject,
    async withOffersAdmin(_hash, op) {
      w.calls.push("db.withOffersAdmin");
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
const call = (deps: PartnerOffersAdminDeps, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}) =>
  handlePartnerOffersAdminRequest(fnReq(FN, method, path, init), deps);

const ROUTES: Array<[string, string, unknown]> = [
  ["GET", "offers?trailId=trl_t", undefined],
  ["POST", "offers", OFFER_BODY],
  ["POST", "offers/approve", { id: ID }],
  ["POST", "offers/end", { id: ID }],
];

describe("routing, Origin, bearer and body order", () => {
  it("OPTIONS is 204 with no port; a foreign Origin is 403; missing bearer is 401", async () => {
    const { w, deps } = world();
    expect((await call(deps, "OPTIONS", "offers", { headers: { origin: ORIGIN, "access-control-request-method": "POST" } })).status).toBe(204);
    expect(w.calls).toEqual([]);
    expect((await call(deps, "GET", "offers?trailId=trl_t", { headers: { origin: "https://evil.example.test", authorization: `Bearer ${SESSION_TOKEN}` } })).status).toBe(403);
    expect((await call(deps, "GET", "offers?trailId=trl_t", { headers: { origin: ORIGIN } })).status).toBe(401);
  });

  it("unknown route 404; wrong method 405", async () => {
    const { deps } = world();
    expect((await call(deps, "POST", "nope", { headers: auth(), body: {} })).status).toBe(404);
    const del = await call(deps, "DELETE", "offers", { headers: auth() });
    expect(del.status).toBe(405);
    expect(del.headers.get("allow")).toBe("GET, POST");
  });
});

describe("strict bodies and AT(14) eligibility", () => {
  it("a stray key is 400 before any port", async () => {
    const { w, deps } = world();
    expect((await call(deps, "POST", "offers", { headers: auth(), body: { ...OFFER_BODY, x: 1 } })).status).toBe(400);
    expect(w.calls).toEqual([]);
  });

  it("invalid eligibility is 422 and never opens the database", async () => {
    const { w, deps } = world();
    const bad = { ...OFFER_BODY, eligibility: { kind: "agg", name: "minConfidence", value: 0.5 } };
    const res = await call(deps, "POST", "offers", { headers: auth(), body: bad });
    expect(res.status).toBe(422);
    expect((await res.json()).error.code).toBe("invalid_eligibility");
    expect(w.calls.filter((c) => c === "db.withOffersAdmin")).toEqual([]);
  });

  it("a valid eligibility reaches the port after the bucket", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "offers", { headers: auth(), body: OFFER_BODY });
    expect(res.status).toBe(200);
    expect(w.calls[0]).toBe("db.hitRateLimit");
    expect(w.calls[1]).toBe("db.withOffersAdmin");
    expect(w.rate[0]).toEqual({ hash: await sha256Hex(SESSION_TOKEN), bucket: OFFERS_BUCKET, windowSeconds: 3600, max: OFFERS_PER_MEMBER_PER_HOUR });
  });
});

describe("status maps", () => {
  it("list returns offers", async () => {
    const { deps } = world();
    const res = await call(deps, "GET", "offers?trailId=trl_t", { headers: auth() });
    expect(res.status).toBe(200);
    expect((await res.json()).data.offers[0].id).toBe(ID);
  });

  for (const [status, code] of [["not_found", "not_found"], ["not_draft", "not_draft"], ["bad_funder", "bad_funder"]] as const) {
    it(`upsert ${status} is 422`, async () => {
      const { w, deps } = world();
      w.upsert = { status, id: status === "not_draft" ? ID : null };
      const res = await call(deps, "POST", "offers", { headers: auth(), body: OFFER_BODY });
      expect(res.status).toBe(422);
      expect((await res.json()).error.code).toBe(code);
      expect(w.committed).toEqual([true]);
    });
  }

  it("approve and end status maps", async () => {
    const { w, deps } = world();
    expect((await call(deps, "POST", "offers/approve", { headers: auth(), body: { id: ID } })).status).toBe(200);
    w.approve = "not_draft";
    expect((await (await call(deps, "POST", "offers/approve", { headers: auth(), body: { id: ID } })).json()).error.code).toBe("not_draft");
    w.end = "not_live";
    expect((await (await call(deps, "POST", "offers/end", { headers: auth(), body: { id: ID } })).json()).error.code).toBe("not_live");
  });
});

describe("thrown refusals", () => {
  it("42501 → 403, 22023 → 422, bind refused → 401", async () => {
    for (const [throwWith, status] of [[new PartnerAuthorityRefused(), 403], [new PartnerInvalidArgument(), 422]] as const) {
      const { w, deps } = world();
      w.throwIn = "upsertOffer";
      w.throwWith = throwWith;
      expect((await call(deps, "POST", "offers", { headers: auth(), body: OFFER_BODY })).status).toBe(status);
      expect(w.rolledBack).toEqual([true]);
    }
    const again = world();
    again.w.bindRefused = true;
    expect((await call(again.deps, "POST", "offers", { headers: auth(), body: OFFER_BODY })).status).toBe(401);
  });
});
