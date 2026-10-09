// supabase/tests/unit/partner-entitlements-handler.test.ts
// The `partner-entitlements` handler and its strict shapes (docs/security/partner-auth-design.md 28; slice S5). Database cells: matrix 36.

import { describe, expect, it } from "vitest";
import { ENTITLEMENTS_BUCKET, handlePartnerEntitlementsRequest } from "../../functions/_shared/partner/entitlements-handler.ts";
import { parseCollectQuery, parseEntitlementRefBody, parseRedeemBody } from "../../functions/_shared/partner/entitlements-shape.ts";
import {
  PartnerAuthorityRefused,
  type HandoverMintResult,
  type PartnerDb,
  type PartnerEntitlementsTx,
  type RedeemResult,
  type VoucherResult,
} from "../../functions/_shared/partner/ports.ts";
import { PARTNER_HANDOVER_TOKEN_RE, sha256Hex } from "../../functions/_shared/partner/token.ts";

const ORIGIN = "https://partners.example.test";
const FN = "partner-entitlements";
const TOKEN = "gr_ps_" + "b".repeat(43);
const ENT = "51000000-0000-0000-0000-000000003601";
let TOKEN_HASH = "";

async function hash(): Promise<string> {
  if (!TOKEN_HASH) TOKEN_HASH = await sha256Hex(TOKEN);
  return TOKEN_HASH;
}

interface FakeEnt {
  readonly db: PartnerDb;
  readonly calls: string[];
  mint: HandoverMintResult;
  redeem: RedeemResult;
  voucher: VoucherResult;
  throwOn?: "authority";
}

function makeFake(overrides: Partial<FakeEnt> = {}): FakeEnt {
  const calls: string[] = [];
  const state: FakeEnt = {
    calls,
    mint: overrides.mint ?? { status: "ok", expiresAt: new Date().toISOString() },
    redeem: overrides.redeem ?? { status: "ok", attestationId: "a1", movement: "redeemed", availability: "low" },
    voucher: overrides.voucher ?? { status: "ok", voucherIssuedAt: new Date().toISOString() },
    throwOn: overrides.throwOn,
    db: null as unknown as PartnerDb,
  };
  const tx: PartnerEntitlementsTx = {
    async collectQueue(facilityId) {
      calls.push(`collect:${facilityId}`);
      return [];
    },
    async mintHandover(facilityId, entitlementId, tokenHash) {
      calls.push(`mint:${facilityId}:${entitlementId}:${tokenHash.length}`);
      return state.mint;
    },
    async redeem(facilityId, entitlementId, method, credential) {
      calls.push(`redeem:${facilityId}:${entitlementId}:${method}:${credential.length}`);
      return state.redeem;
    },
    async voucher(facilityId, entitlementId) {
      calls.push(`voucher:${facilityId}:${entitlementId}`);
      return state.voucher;
    },
  };
  state.db = {
    withMint: () => Promise.reject(new Error("unused")),
    withInviteMint: () => Promise.reject(new Error("unused")),
    withSession: () => Promise.reject(new Error("unused")),
    withInvites: () => Promise.reject(new Error("unused")),
    withMembers: () => Promise.reject(new Error("unused")),
    withAttest: () => Promise.reject(new Error("unused")),
    withReview: () => Promise.reject(new Error("unused")),
    withStock: () => Promise.reject(new Error("unused")),
    async withEntitlements(_h, op) {
      calls.push("withEntitlements");
      if (state.throwOn === "authority") throw new PartnerAuthorityRefused();
      return await op(tx);
    },
    async hitRateLimit(_h, bucket) {
      calls.push(`hitRateLimit:${bucket}`);
      return { ok: true, retryAfterSeconds: 0 };
    },
    async hitSystemRateLimit() {
      return { ok: true, retryAfterSeconds: 0 };
    },
  };
  return state;
}

async function call(fake: FakeEnt, method: string, path: string, body?: unknown): Promise<Response> {
  const headers = new Headers({ origin: ORIGIN, authorization: `Bearer ${TOKEN}` });
  let init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers.set("content-type", "application/json");
    init = { method, headers, body: JSON.stringify(body) };
  }
  return await handlePartnerEntitlementsRequest(new Request(`https://project.example.test/functions/v1/${FN}/${path}`, init), {
    db: fake.db,
    allowedOrigin: ORIGIN,
  });
}

describe("entitlements-shape", () => {
  it("parses collect, mint ref and redeem bodies", () => {
    expect(parseCollectQuery("https://x/collect?facilityId=fac_x").ok).toBe(true);
    expect(parseEntitlementRefBody({ facilityId: "fac_x", entitlementId: ENT }).ok).toBe(true);
    expect(parseRedeemBody({ facilityId: "fac_x", entitlementId: ENT, method: "staff_scan", credential: "36200000-0000-0000-0000-000000000001" }).ok).toBe(true);
    expect(parseRedeemBody({ facilityId: "fac_x", entitlementId: ENT, method: "offline_code", credential: "123456" }).ok).toBe(false);
  });
});

describe("partner-entitlements handler", () => {
  it("GET collect hits the member bucket", async () => {
    await hash();
    const fake = makeFake();
    const res = await call(fake, "GET", "collect?facilityId=fac_x");
    expect(res.status).toBe(200);
    expect(fake.calls[0]).toBe(`hitRateLimit:${ENTITLEMENTS_BUCKET}`);
  });

  it("POST handover/mint returns a gr_ho_ token once on ok", async () => {
    await hash();
    const fake = makeFake();
    const res = await call(fake, "POST", "handover/mint", { facilityId: "fac_x", entitlementId: ENT });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.token).toMatch(PARTNER_HANDOVER_TOKEN_RE);
    expect(fake.calls.some((c) => c.startsWith("mint:"))).toBe(true);
  });

  it("POST redeem maps out_of_stock to 409 and hashes hand_over_token", async () => {
    await hash();
    const oos = makeFake({ redeem: { status: "out_of_stock", attestationId: null, movement: null, availability: "out" } });
    expect((await call(oos, "POST", "redeem", {
      facilityId: "fac_x",
      entitlementId: ENT,
      method: "hand_over_token",
      credential: "gr_ho_" + "c".repeat(43),
    })).status).toBe(409);
    expect(oos.calls.some((c) => c.includes("hand_over_token:64"))).toBe(true);
  });

  it("POST voucher returns 200 on ok", async () => {
    await hash();
    const fake = makeFake();
    expect((await call(fake, "POST", "voucher", { facilityId: "fac_x", entitlementId: ENT })).status).toBe(200);
  });
});
