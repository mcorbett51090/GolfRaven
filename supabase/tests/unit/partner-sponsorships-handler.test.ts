// supabase/tests/unit/partner-sponsorships-handler.test.ts
//
// The `sponsorships-admin` handler and its strict shapes (docs/security/partner-auth-design.md 12, 30; AT(20); slice S6, the Edge half of 0059), against an in-memory `PartnerDb`.

import { describe, expect, it } from "vitest";
import {
  type PartnerDb,
  type PartnerSponsorshipsTx,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
  type SponsorshipApproveStatus,
  type SponsorshipRow,
  type SponsorshipUpsertResult,
} from "../../functions/_shared/partner/ports.ts";
import {
  handlePartnerSponsorshipsRequest,
  SPONSORSHIPS_BUCKET,
  SPONSORSHIPS_PER_MEMBER_PER_HOUR,
  type PartnerSponsorshipsDeps,
} from "../../functions/_shared/partner/sponsorships-handler.ts";
import { fnReq, ORIGIN, SESSION_TOKEN, sha256Hex } from "./partner-fakes.ts";

const FN = "sponsorships-admin";
const ID = "00000000-0000-4000-8000-0000000000bb";
const ORG = "00000000-0000-4000-8000-0000000000cc";
const BODY = {
  sponsorOrgId: ORG,
  trailId: "trl_t",
  category: "equipment",
  scope: "special_marker",
  attributionName: "Acme",
};

interface World {
  calls: string[];
  committed: boolean[];
  rolledBack: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  rows: SponsorshipRow[];
  upsert: SponsorshipUpsertResult;
  approve: SponsorshipApproveStatus;
  throwIn: string | null;
  throwWith: Error;
  rateOk: boolean;
  bindRefused: boolean;
}

function world(): { w: World; deps: PartnerSponsorshipsDeps } {
  const w: World = {
    calls: [],
    committed: [],
    rolledBack: [],
    rate: [],
    rows: [{
      id: ID,
      sponsorOrgId: ORG,
      trailId: "trl_t",
      category: "equipment",
      scope: "special_marker",
      attributionName: "Acme",
      attributionAsset: null,
      placementFee: null,
      startsOn: null,
      endsOn: null,
      operatorApprovedAt: null,
      status: "draft",
    }],
    upsert: { status: "ok", id: ID },
    approve: "ok",
    throwIn: null,
    throwWith: new PartnerAuthorityRefused(),
    rateOk: true,
    bindRefused: false,
  };
  const tx: PartnerSponsorshipsTx = {
    async listSponsorships(trailId) {
      w.calls.push("tx.listSponsorships");
      if (w.throwIn === "listSponsorships") throw w.throwWith;
      return w.rows.map((r) => ({ ...r, trailId }));
    },
    async upsertSponsorship(...args) {
      w.calls.push("tx.upsertSponsorship");
      w.calls.push(`args:${JSON.stringify(args.slice(0, 4))}`);
      if (w.throwIn === "upsertSponsorship") throw w.throwWith;
      return w.upsert;
    },
    async approveSponsorship(id) {
      w.calls.push("tx.approveSponsorship");
      w.calls.push(`id:${id}`);
      if (w.throwIn === "approveSponsorship") throw w.throwWith;
      return w.approve;
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
    withOffersRedeem: reject,
    withSettlementExport: reject,
    async withSponsorships(_hash, op) {
      w.calls.push("db.withSponsorships");
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
const call = (deps: PartnerSponsorshipsDeps, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown } = {}) =>
  handlePartnerSponsorshipsRequest(fnReq(FN, method, path, init), deps);

const ROUTES: Array<[string, string, unknown]> = [
  ["GET", "sponsorships?trailId=trl_t", undefined],
  ["POST", "sponsorships", BODY],
  ["POST", "sponsorships/approve", { id: ID }],
];

describe("routing, Origin, bearer and body order", () => {
  it("OPTIONS is 204; foreign Origin 403; no bearer 401", async () => {
    const { w, deps } = world();
    expect((await call(deps, "OPTIONS", "sponsorships", { headers: { origin: ORIGIN, "access-control-request-method": "POST" } })).status).toBe(204);
    expect(w.calls).toEqual([]);
    expect((await call(deps, "GET", "sponsorships?trailId=trl_t", { headers: { origin: "https://evil.example.test", authorization: `Bearer ${SESSION_TOKEN}` } })).status).toBe(403);
    expect((await call(deps, "GET", "sponsorships?trailId=trl_t", { headers: { origin: ORIGIN } })).status).toBe(401);
  });

  it("unknown route 404; wrong method 405", async () => {
    const { deps } = world();
    expect((await call(deps, "POST", "nope", { headers: auth(), body: {} })).status).toBe(404);
    const del = await call(deps, "DELETE", "sponsorships", { headers: auth() });
    expect(del.status).toBe(405);
    expect(del.headers.get("allow")).toBe("GET, POST");
  });
});

describe("strict bodies and the bucket", () => {
  it("a stray key is 400 before any port", async () => {
    const { w, deps } = world();
    expect((await call(deps, "POST", "sponsorships", { headers: auth(), body: { ...BODY, x: 1 } })).status).toBe(400);
    expect(w.calls).toEqual([]);
  });

  it("one per-member hit precedes the work", async () => {
    const { w, deps } = world();
    expect((await call(deps, "GET", "sponsorships?trailId=trl_t", { headers: auth() })).status).toBe(200);
    expect(w.calls[0]).toBe("db.hitRateLimit");
    expect(w.calls[1]).toBe("db.withSponsorships");
    expect(w.rate[0]).toEqual({ hash: await sha256Hex(SESSION_TOKEN), bucket: SPONSORSHIPS_BUCKET, windowSeconds: 3600, max: SPONSORSHIPS_PER_MEMBER_PER_HOUR });
  });

  it("an exhausted bucket is 429", async () => {
    const { w, deps } = world();
    w.rateOk = false;
    for (const [method, path, body] of ROUTES) {
      expect((await call(deps, method, path, { headers: auth(), body })).status).toBe(429);
    }
    expect(w.calls.filter((c) => c === "db.withSponsorships")).toEqual([]);
  });
});

describe("status maps including AT(20) stock_short", () => {
  it("list and upsert ok", async () => {
    const { deps } = world();
    expect((await call(deps, "GET", "sponsorships?trailId=trl_t", { headers: auth() })).status).toBe(200);
    const res = await call(deps, "POST", "sponsorships", { headers: auth(), body: BODY });
    expect(res.status).toBe(200);
    expect((await res.json()).data.id).toBe(ID);
  });

  for (const status of ["not_found", "not_draft", "bad_sponsor"] as const) {
    it(`upsert ${status} is 422`, async () => {
      const { w, deps } = world();
      w.upsert = { status, id: status === "not_draft" ? ID : null };
      const res = await call(deps, "POST", "sponsorships", { headers: auth(), body: BODY });
      expect(res.status).toBe(422);
      expect((await res.json()).error.code).toBe(status);
      expect(w.committed).toEqual([true]);
    });
  }

  it("approve stock_short is 422 and the transaction COMMITS", async () => {
    const { w, deps } = world();
    w.approve = "stock_short";
    const res = await call(deps, "POST", "sponsorships/approve", { headers: auth(), body: { id: ID } });
    expect(res.status).toBe(422);
    expect((await res.json()).error.code).toBe("stock_short");
    expect(w.committed).toEqual([true]);
    expect(w.rolledBack).toEqual([]);
  });

  it("approve ok is 200", async () => {
    const { deps } = world();
    expect((await call(deps, "POST", "sponsorships/approve", { headers: auth(), body: { id: ID } })).status).toBe(200);
  });
});

describe("thrown refusals", () => {
  it("42501 → 403, 22023 → 422, bind refused → 401", async () => {
    for (const [throwWith, status] of [[new PartnerAuthorityRefused(), 403], [new PartnerInvalidArgument(), 422]] as const) {
      const { w, deps } = world();
      w.throwIn = "upsertSponsorship";
      w.throwWith = throwWith;
      expect((await call(deps, "POST", "sponsorships", { headers: auth(), body: BODY })).status).toBe(status);
      expect(w.rolledBack).toEqual([true]);
    }
    const again = world();
    again.w.bindRefused = true;
    expect((await call(again.deps, "POST", "sponsorships", { headers: auth(), body: BODY })).status).toBe(401);
  });
});
