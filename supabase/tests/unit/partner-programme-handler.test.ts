// supabase/tests/unit/partner-programme-handler.test.ts
//
// The `programme-config` handler and its strict shapes (docs/security/partner-auth-design.md 12, 30; slice S6, the Edge half of 0059), against an in-memory `PartnerDb`. What is decided HERE: the route table, the
// Origin / bearer / media-type / strict-body order, that every route is a session route, the status-to-HTTP map, and that the arguments reach the port exactly as validated.

import { describe, expect, it } from "vitest";
import {
  handlePartnerProgrammeRequest,
  PROGRAMME_BUCKET,
  PROGRAMME_PER_MEMBER_PER_HOUR,
  type PartnerProgrammeDeps,
} from "../../functions/_shared/partner/programme-handler.ts";
import {
  type FacilityProgrammeRow,
  type FacilityProgrammeUpsertStatus,
  type OperatorRollupRow,
  type PartnerDb,
  type PartnerProgrammeTx,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
  type SponsorRollupRow,
  type TrailProgrammeRow,
  type TrailProgrammeUpsertStatus,
} from "../../functions/_shared/partner/ports.ts";
import { fnReq, ORIGIN, SESSION_TOKEN, sha256Hex } from "./partner-fakes.ts";

const FN = "programme-config";

interface World {
  calls: string[];
  committed: boolean[];
  rolledBack: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  trail: TrailProgrammeRow;
  facilities: FacilityProgrammeRow[];
  trailUpsert: TrailProgrammeUpsertStatus;
  facilityUpsert: FacilityProgrammeUpsertStatus;
  operatorRows: OperatorRollupRow[];
  sponsorRows: SponsorRollupRow[];
  throwIn: string | null;
  throwWith: Error;
  rateOk: boolean;
  bindRefused: boolean;
}

const okTrail: TrailProgrammeRow = {
  status: "ok",
  trailId: "trl_t",
  programmeStatus: "live",
  markerSource: "programme_marker",
  markerRequiresCompletion: true,
  specialMarkerFundedBy: "trail",
  specialMarkerLowThreshold: 5,
  webPlayerFlow: false,
  specialMarkerSku: "sku",
  specialMarkerSponsorshipId: null,
  feeModel: "none",
  feeAmount: null,
  startsOn: "2030-01-01",
  endsOn: null,
};

const TRAIL_BODY = {
  trailId: "trl_t",
  status: "live",
  markerSource: "programme_marker",
  markerRequiresCompletion: true,
  specialMarkerLowThreshold: 5,
  webPlayerFlow: false,
};

const FAC_BODY = {
  trailId: "trl_t",
  facilityId: "fac_x",
  participation: "accepted",
  qrMode: "rotating",
};

function world(): { w: World; deps: PartnerProgrammeDeps } {
  const w: World = {
    calls: [],
    committed: [],
    rolledBack: [],
    rate: [],
    trail: okTrail,
    facilities: [{
      facilityId: "fac_x",
      participation: "accepted",
      stocksMarkers: true,
      holdsSpecialMarker: false,
      connectivity: "ok",
      staffNetwork: true,
      wifiNote: null,
      qrMode: "rotating",
      pinEpoch: 1,
    }],
    trailUpsert: "ok",
    facilityUpsert: "ok",
    operatorRows: [{ trailId: "trl_t", month: "2030-01-01", metric: "redemptions", value: 3, cohortN: 2 }],
    sponsorRows: [],
    throwIn: null,
    throwWith: new PartnerAuthorityRefused(),
    rateOk: true,
    bindRefused: false,
  };
  const tx: PartnerProgrammeTx = {
    async trailRead(trailId) {
      w.calls.push("tx.trailRead");
      if (w.throwIn === "trailRead") throw w.throwWith;
      return { ...w.trail, trailId: w.trail.status === "ok" ? trailId : null };
    },
    async facilityList(trailId) {
      w.calls.push("tx.facilityList");
      if (w.throwIn === "facilityList") throw w.throwWith;
      return w.facilities.map((f) => ({ ...f, facilityId: f.facilityId || trailId }));
    },
    async trailUpsert(...args) {
      w.calls.push("tx.trailUpsert");
      w.calls.push(`args:${JSON.stringify(args)}`);
      if (w.throwIn === "trailUpsert") throw w.throwWith;
      return w.trailUpsert;
    },
    async facilityUpsert(...args) {
      w.calls.push("tx.facilityUpsert");
      w.calls.push(`args:${JSON.stringify(args)}`);
      if (w.throwIn === "facilityUpsert") throw w.throwWith;
      return w.facilityUpsert;
    },
    async operatorRollup(trailId) {
      w.calls.push("tx.operatorRollup");
      if (w.throwIn === "operatorRollup") throw w.throwWith;
      return w.operatorRows.map((r) => ({ ...r, trailId }));
    },
    async sponsorRollup(id) {
      w.calls.push("tx.sponsorRollup");
      if (w.throwIn === "sponsorRollup") throw w.throwWith;
      return w.sponsorRows.map((r) => ({ ...r, sponsorshipId: id }));
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
    withOffersAdmin: reject,
    withSponsorships: reject,
    withOffersRedeem: reject,
    withSettlementExport: reject,
    async withProgramme(_hash, op) {
      w.calls.push("db.withProgramme");
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
const call = (deps: PartnerProgrammeDeps, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}) =>
  handlePartnerProgrammeRequest(fnReq(FN, method, path, init), deps);

const ROUTES: Array<[string, string, unknown]> = [
  ["GET", "programme?trailId=trl_t", undefined],
  ["POST", "programme/trail", TRAIL_BODY],
  ["POST", "programme/facility", FAC_BODY],
  ["GET", "rollups/operator?trailId=trl_t", undefined],
  ["GET", "rollups/sponsor?sponsorshipId=00000000-0000-4000-8000-000000000001", undefined],
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
    const post = await call(deps, "POST", "programme?trailId=trl_t", { headers: auth(), body: {} });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET");
  });

  it("the exact JSON media type is required (415) before the body is read, and nothing reaches the database", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "programme/trail", { headers: auth({ "content-type": "text/plain; x=application/json" }), raw: JSON.stringify(TRAIL_BODY) });
    expect(res.status).toBe(415);
    expect(w.calls).toEqual([]);
  });
});

describe("strict bodies and queries: unknown keys and malformed values are 400, before any port", () => {
  it("POST programme/trail with a stray key is 400", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "programme/trail", { headers: auth(), body: { ...TRAIL_BODY, extra: 1 } });
    expect(res.status).toBe(400);
    expect(w.calls).toEqual([]);
  });
  for (const q of ["programme", "programme?trailId=", "programme?trailId=trl%20t", "programme?trailId=trl_t&x=1"]) {
    it(`GET ${q} is 400 and touches no port`, async () => {
      const { w, deps } = world();
      expect((await call(deps, "GET", q, { headers: auth() })).status).toBe(400);
      expect(w.calls).toEqual([]);
    });
  }
});

describe("the bucket", () => {
  it("one per-member hit precedes the work", async () => {
    const { w, deps } = world();
    expect((await call(deps, "GET", "programme?trailId=trl_t", { headers: auth() })).status).toBe(200);
    expect(w.calls[0]).toBe("db.hitRateLimit");
    expect(w.calls[1]).toBe("db.withProgramme");
    expect(w.rate[0]).toEqual({ hash: await sha256Hex(SESSION_TOKEN), bucket: PROGRAMME_BUCKET, windowSeconds: 3600, max: PROGRAMME_PER_MEMBER_PER_HOUR });
  });

  it("an exhausted bucket is 429 with Retry-After and the work never opens", async () => {
    const { w, deps } = world();
    w.rateOk = false;
    for (const [method, path, body] of ROUTES) {
      const res = await call(deps, method, path, { headers: auth(), body });
      expect(res.status, path).toBe(429);
      expect(res.headers.get("retry-after")).toBe("3600");
    }
    expect(w.calls.filter((c) => c === "db.withProgramme")).toEqual([]);
  });
});

describe("GET programme and rollups", () => {
  it("returns trail + facilities", async () => {
    const { deps } = world();
    const res = await call(deps, "GET", "programme?trailId=trl_t", { headers: auth() });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.trail.trailId).toBe("trl_t");
    expect(body.data.facilities).toHaveLength(1);
  });

  it("not_found on trail read is 422", async () => {
    const { w, deps } = world();
    w.trail = { ...okTrail, status: "not_found", trailId: null, programmeStatus: null };
    const res = await call(deps, "GET", "programme?trailId=trl_t", { headers: auth() });
    expect(res.status).toBe(422);
    expect((await res.json()).error.code).toBe("not_found");
  });

  it("operator rollup returns rows", async () => {
    const { deps } = world();
    const res = await call(deps, "GET", "rollups/operator?trailId=trl_t", { headers: auth() });
    expect(res.status).toBe(200);
    expect((await res.json()).data.rollups[0].metric).toBe("redemptions");
  });
});

describe("POST upserts: the status map", () => {
  it("trail upsert ok is 200; not_found is 422", async () => {
    const { w, deps } = world();
    expect((await call(deps, "POST", "programme/trail", { headers: auth(), body: TRAIL_BODY })).status).toBe(200);
    w.trailUpsert = "not_found";
    const res = await call(deps, "POST", "programme/trail", { headers: auth(), body: TRAIL_BODY });
    expect(res.status).toBe(422);
    expect((await res.json()).error.code).toBe("not_found");
  });

  it("facility upsert no_trail is 422", async () => {
    const { w, deps } = world();
    w.facilityUpsert = "no_trail";
    const res = await call(deps, "POST", "programme/facility", { headers: auth(), body: FAC_BODY });
    expect(res.status).toBe(422);
    expect((await res.json()).error.code).toBe("no_trail");
  });
});

describe("thrown refusals roll back and map", () => {
  it("42501 is 403, 22023 is 422, a refused bind is the ONE 401", async () => {
    for (const [throwWith, status] of [[new PartnerAuthorityRefused(), 403], [new PartnerInvalidArgument(), 422]] as const) {
      const { w, deps } = world();
      w.throwIn = "trailUpsert";
      w.throwWith = throwWith;
      const res = await call(deps, "POST", "programme/trail", { headers: auth(), body: TRAIL_BODY });
      expect(res.status).toBe(status);
      expect(w.rolledBack).toEqual([true]);
    }
    const { w, deps } = world();
    w.bindRefused = true;
    expect((await call(deps, "POST", "programme/trail", { headers: auth(), body: TRAIL_BODY })).status).toBe(401);
  });
});
