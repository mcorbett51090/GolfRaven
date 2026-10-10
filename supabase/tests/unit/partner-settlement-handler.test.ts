// supabase/tests/unit/partner-settlement-handler.test.ts
//
// The `settlement-export` handler (docs/security/partner-auth-design.md 12, 32; AT(17), AT(20); P5.1b). Database cells: matrix 38. Storage is a port.

import { describe, expect, it } from "vitest";
import {
  handleSettlementExportRequest,
  SETTLEMENT_BUCKET,
  SETTLEMENT_PER_MEMBER_PER_HOUR,
  SETTLEMENT_SIGNED_URL_SECONDS,
  settlementCsv,
  type SettlementExportDeps,
} from "../../functions/_shared/partner/settlement-handler.ts";
import { parseSettlementExportBody } from "../../functions/_shared/partner/settlement-shape.ts";
import {
  type ExportsStoragePort,
  type PartnerDb,
  type PartnerSettlementExportTx,
  PartnerAuthorityRefused,
  PartnerSessionRefused,
  type SettlementExportResult,
  type SettlementLine,
} from "../../functions/_shared/partner/ports.ts";
import { fnReq, ORIGIN, SESSION_TOKEN } from "./partner-fakes.ts";

const FN = "settlement-export";
const SPONSORSHIP = "79000000-0000-0000-0000-000000000001";

const line: SettlementLine = {
  facilityId: "fac_x",
  month: "2030-01-01",
  funder: "sponsor",
  sponsorshipId: SPONSORSHIP,
  redemptions: 2,
  offlineCount: 0,
  unconfirmedCount: 0,
  faceValueTotal: 10,
};

interface World {
  calls: string[];
  committed: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  exportResult: SettlementExportResult;
  putArgs: Array<{ path: string; contentType: string; expiresInSeconds: number; bytes: number }>;
  throwExport: Error | null;
  bindRefused: boolean;
  rateOk: boolean;
}

function world(): { w: World; deps: SettlementExportDeps } {
  const w: World = {
    calls: [],
    committed: [],
    rate: [],
    exportResult: { status: "ok", lines: [line] },
    putArgs: [],
    throwExport: null,
    bindRefused: false,
    rateOk: true,
  };
  const tx: PartnerSettlementExportTx = {
    async settlementExport(trailId, month) {
      w.calls.push(`tx.settlementExport:${trailId}:${month}`);
      if (w.throwExport) throw w.throwExport;
      return w.exportResult;
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
    withOffersRedeem: reject,
    async withSettlementExport(_hash, op) {
      w.calls.push("db.withSettlementExport");
      if (w.bindRefused) throw new PartnerSessionRefused();
      const r = await op(tx);
      w.committed.push(true);
      return r;
    },
    async hitRateLimit(hash, bucket, windowSeconds, max) {
      w.calls.push("db.hitRateLimit");
      w.rate.push({ hash, bucket, windowSeconds, max });
      return w.rateOk ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds: 3600 };
    },
    hitSystemRateLimit: reject,
  };
  const storage: ExportsStoragePort = {
    async putSigned(path, body, contentType, expiresInSeconds) {
      w.calls.push("storage.putSigned");
      w.putArgs.push({ path, contentType, expiresInSeconds, bytes: body.byteLength });
      return { path, signedUrl: `https://signed.test/${path}`, expiresAt: "2030-01-08T00:00:00.000Z" };
    },
    async purgeOlderThan() {
      throw new Error("not used");
    },
  };
  return {
    w,
    deps: {
      db,
      storage,
      allowedOrigin: ORIGIN,
      nowMs: () => Date.parse("2030-01-01T00:00:00.000Z"),
      newId: () => "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    },
  };
}

const auth = () => ({ origin: ORIGIN, authorization: `Bearer ${SESSION_TOKEN}` });
const call = (deps: SettlementExportDeps, body: unknown) =>
  handleSettlementExportRequest(fnReq(FN, "POST", "export", { headers: auth(), body }), deps);

describe("settlement-shape and CSV", () => {
  it("parseSettlementExportBody accepts YYYY-MM-DD; refuses unknown keys", () => {
    expect(parseSettlementExportBody({ trailId: "trl_t", month: "2030-01-15" })).toEqual({
      ok: true,
      value: { trailId: "trl_t", month: "2030-01-15" },
    });
    expect(parseSettlementExportBody({ trailId: "trl_t", month: "2030-01", extra: 1 }).ok).toBe(false);
  });

  it("settlementCsv always includes sponsorship_id column (AT(20))", () => {
    const csv = settlementCsv([line, { ...line, sponsorshipId: null, funder: "trail" }]);
    expect(csv.split("\n")[0]).toBe("facility_id,month,funder,sponsorship_id,redemptions,offline_count,unconfirmed_count,face_value_total");
    expect(csv).toContain(`,${SPONSORSHIP},2,`);
    expect(csv).toContain(",trail,,2,");
  });
});

describe("settlement-export handler", () => {
  it("POST export: role-checked definer then signed URL (AT(17))", async () => {
    const { w, deps } = world();
    const res = await call(deps, { trailId: "trl_t", month: "2030-01-01" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { signedUrl: string; path: string; lines: Array<{ sponsorshipId: string }> } };
    expect(body.data.signedUrl).toBe("https://signed.test/settlement/trl_t/2030-01-01/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.csv");
    expect(body.data.path).toBe("settlement/trl_t/2030-01-01/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.csv");
    expect(body.data.lines[0]!.sponsorshipId).toBe(SPONSORSHIP);
    expect(w.calls).toEqual(["db.hitRateLimit", "db.withSettlementExport", "tx.settlementExport:trl_t:2030-01-01", "storage.putSigned"]);
    expect(w.rate[0]).toMatchObject({ bucket: SETTLEMENT_BUCKET, max: SETTLEMENT_PER_MEMBER_PER_HOUR });
    expect(w.putArgs[0]?.expiresInSeconds).toBe(SETTLEMENT_SIGNED_URL_SECONDS);
    expect(w.putArgs[0]?.contentType).toBe("text/csv");
  });

  it("empty → 404; 42501 → 403; no storage on empty", async () => {
    const a = world();
    a.w.exportResult = { status: "empty", lines: [] };
    const r1 = await call(a.deps, { trailId: "trl_t", month: "2030-01-01" });
    expect(r1.status).toBe(404);
    expect(a.w.calls).not.toContain("storage.putSigned");

    const b = world();
    b.w.throwExport = new PartnerAuthorityRefused();
    const r2 = await call(b.deps, { trailId: "trl_t", month: "2030-01-01" });
    expect(r2.status).toBe(403);
  });
});
