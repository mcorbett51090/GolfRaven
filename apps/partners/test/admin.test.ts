/**
 * S7d manager/operator/admin screens: open programme/offers/review, A0 loads, A3 writes gated on aal/TOTP, approve flow.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController, type AppState, type SignedInState } from "../src/app/controller";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { API_BASE, makeWorld } from "./support/world";

const TRAIL = "trl_demo";
const FACILITY = "44444444-4444-4444-8444-444444444444";
const OFFER_ID = "61000000-0000-0000-0000-000000006101";
const REVIEW_ID = "81000000-0000-0000-0000-000000008101";
const RECEIPT_CROSS_USER_ID = "91000000-0000-0000-0000-000000009101";

const operatorWhoami = {
  aal: 2,
  requiredAal: 2,
  isAdmin: false,
  memberships: [{ orgId: "33333333-3333-4333-8333-333333333333", role: "operator", facilityIds: [FACILITY], trailIds: [TRAIL] }],
};

const adminWhoami = {
  aal: 2,
  requiredAal: 2,
  isAdmin: true,
  memberships: [{ orgId: "33333333-3333-4333-8333-333333333333", role: "operator", facilityIds: [FACILITY], trailIds: [TRAIL] }],
};

const staffLowAal = {
  aal: 1,
  requiredAal: 1,
  isAdmin: false,
  memberships: [{ orgId: "33333333-3333-4333-8333-333333333333", role: "operator", facilityIds: [FACILITY], trailIds: [TRAIL] }],
};

async function setup(whoami: typeof operatorWhoami) {
  const w = makeWorld({ whoami });
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
  const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
  const states: AppState[] = [];
  controller.subscribe((s) => states.push(s));
  await controller.signIn();
  return { w, api, controller, states };
}

const home = (c: Awaited<ReturnType<typeof setup>>["controller"]): SignedInState => {
  const s = c.getState();
  if (s.screen !== "signed-in") throw new Error(`expected signed-in, got ${s.screen}`);
  return s;
};

async function until(cond: () => boolean, label: string): Promise<void> {
  for (let i = 0; i < 400; i += 1) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(label);
}

let spies: StorageSpies;
beforeEach(() => {
  spies = installStorageSpies();
});
afterEach(() => spies.restore());

describe("S7d programme screen", () => {
  it("opens from home and loads programme (A0)", async () => {
    const s = await setup(operatorWhoami);
    s.controller.openProgramme(TRAIL);
    expect(home(s.controller).work?.kind).toBe("programme");
    await s.controller.loadProgramme();
    await until(() => {
      const w = home(s.controller).work;
      return w?.kind === "programme" && w.trail !== null;
    }, "programme never loaded");
    const w = home(s.controller).work;
    expect(w?.kind).toBe("programme");
    if (w?.kind === "programme") {
      expect(w.trail?.status).toBe("pilot");
      expect(w.facilities?.[0]?.facilityId).toBe(FACILITY);
    }
    const gets = s.w.server.log.filter((r) => r.method === "GET" && r.path.endsWith("/programme-config/programme"));
    expect(gets.length).toBeGreaterThanOrEqual(1);
  });

  it("refuses trail upsert when aal is below 2 (A3 client gate)", async () => {
    const s = await setup(staffLowAal);
    s.controller.openProgramme(TRAIL);
    await s.controller.saveTrailProgramme({
      trailId: TRAIL,
      status: "pilot",
      markerSource: "any_purchase",
      markerRequiresCompletion: false,
      specialMarkerFundedBy: null,
      specialMarkerLowThreshold: 3,
      webPlayerFlow: true,
      specialMarkerSku: null,
      specialMarkerSponsorshipId: null,
      feeModel: null,
      feeAmount: null,
      startsOn: null,
      endsOn: null,
    });
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "admin.needTotp" } });
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/programme-config/programme/trail"));
    expect(posts).toHaveLength(0);
  });

  it("saves trail programme when aal 2 (A3)", async () => {
    const s = await setup(operatorWhoami);
    s.controller.openProgramme(TRAIL);
    await s.controller.saveTrailProgramme({
      trailId: TRAIL,
      status: "live",
      markerSource: "programme_marker",
      markerRequiresCompletion: true,
      specialMarkerFundedBy: "trail",
      specialMarkerLowThreshold: 5,
      webPlayerFlow: false,
      specialMarkerSku: "SKU-1",
      specialMarkerSponsorshipId: null,
      feeModel: "none",
      feeAmount: null,
      startsOn: "2026-01-01",
      endsOn: "2026-12-31",
    });
    await until(() => home(s.controller).notice?.kind === "programme-saved", "programme save never completed");
    expect(home(s.controller).notice).toEqual({ kind: "programme-saved" });
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/programme-config/programme/trail"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toMatchObject({ trailId: TRAIL, status: "live", markerSource: "programme_marker" });
  });
});

describe("S7d offers screen", () => {
  it("loads offers (A0) and approves a draft after A3", async () => {
    const s = await setup(adminWhoami);
    s.controller.openOffers(TRAIL);
    expect(home(s.controller).work?.kind).toBe("offers");
    await s.controller.loadOffers();
    await until(() => {
      const w = home(s.controller).work;
      return w?.kind === "offers" && w.offers !== null;
    }, "offers never loaded");
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("offers");
      if (w?.kind === "offers") {
        expect(w.offers?.[0]?.budgetCap).toBe(100);
        expect(w.offers?.[0]?.status).toBe("draft");
      }
    }

    await s.controller.approveOffer(OFFER_ID);
    await until(() => home(s.controller).notice?.kind === "offer-approved", "approve never completed");
    expect(home(s.controller).notice).toEqual({ kind: "offer-approved" });
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/offers-admin/offers/approve"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({ id: OFFER_ID });
  });

  it("creates a draft offer (A3) and returns id", async () => {
    const s = await setup(operatorWhoami);
    s.controller.openOffers(TRAIL);
    await s.controller.saveOffer({
      id: null,
      trailId: TRAIL,
      facilityId: FACILITY,
      eligibility: { all: true },
      funder: "course",
      sponsorshipId: null,
      budgetCap: 50,
      maxRedemptions: 10,
      faceValue: 5,
      validFrom: "2026-01-01",
      validTo: "2026-06-30",
    });
    await until(() => home(s.controller).notice?.kind === "offer-saved", "offer save never completed");
    const w = home(s.controller).work;
    expect(w?.kind).toBe("offers");
    if (w?.kind === "offers") expect(w.lastId).toMatch(/^[0-9a-f-]{36}$/i);
  });
});

describe("S7d review screen", () => {
  it("loads queue + SLA (A0) and resolves an offer code (A3)", async () => {
    const s = await setup(adminWhoami);
    s.controller.openReview();
    expect(home(s.controller).work?.kind).toBe("review");
    await s.controller.loadReview();
    await until(() => {
      const w = home(s.controller).work;
      return w?.kind === "review" && w.items !== null && w.sla !== null;
    }, "review never loaded");
    {
      const w = home(s.controller).work;
      if (w?.kind === "review") {
        expect(w.items?.[0]?.handle).toBe("player_one");
        expect(w.items?.some((i) => i.reviewKind === "receipt_cross_user_match")).toBe(true);
        expect(w.sla?.slaHours).toBe(48);
      }
    }

    await s.controller.resolveOfferCode(REVIEW_ID, true);
    await until(() => home(s.controller).notice?.kind === "review-resolved", "resolve never completed");
    expect(home(s.controller).notice).toEqual({ kind: "review-resolved" });
    const w = home(s.controller).work;
    if (w?.kind === "review") expect(w.lastState).toBe("approved");
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-review/resolve/offer-code"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({ id: REVIEW_ID, approve: true });
  });

  it("resolves a receipt_cross_user_match review item (A3)", async () => {
    const s = await setup(adminWhoami);
    s.controller.openReview();
    await s.controller.loadReview();
    await until(() => {
      const w = home(s.controller).work;
      return w?.kind === "review" && (w.items?.some((i) => i.id === RECEIPT_CROSS_USER_ID) ?? false);
    }, "receipt cross-user item never loaded");

    await s.controller.resolveReceiptCrossUser(RECEIPT_CROSS_USER_ID, false);
    await until(() => home(s.controller).notice?.kind === "review-resolved", "receipt cross-user resolve never completed");
    expect(home(s.controller).notice).toEqual({ kind: "review-resolved" });
    const w = home(s.controller).work;
    if (w?.kind === "review") expect(w.lastState).toBe("rejected");
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-review/resolve/receipt-cross-user"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({ id: RECEIPT_CROSS_USER_ID, approve: false });
  });

  it("loads receipt_cross_user preview images on the review queue (A0; never logs signedUrl)", async () => {
    const s = await setup(adminWhoami);
    s.controller.openReview();
    await s.controller.loadReview();
    await until(() => {
      const w = home(s.controller).work;
      return w?.kind === "review" && w.previews[RECEIPT_CROSS_USER_ID] !== undefined;
    }, "receipt preview never loaded");
    const w = home(s.controller).work;
    expect(w?.kind).toBe("review");
    if (w?.kind === "review") {
      const preview = w.previews[RECEIPT_CROSS_USER_ID];
      expect(preview?.images.map((i) => i.label)).toEqual(["subject", "matched"]);
      expect(preview?.images.every((i) => i.signedUrl.includes("token="))).toBe(true);
    }
    const gets = s.w.server.log.filter((r) => r.method === "GET" && r.path.endsWith("/partner-review/preview/receipt-cross-user"));
    expect(gets.length).toBeGreaterThanOrEqual(1);
    const logBlob = JSON.stringify(s.w.server.log);
    expect(logBlob).not.toMatch(/fake-preview-token|signedUrl/i);
  });

  it("staff without isAdmin cannot open review", async () => {
    const s = await setup(operatorWhoami);
    s.controller.openReview();
    expect(home(s.controller).work).toBeNull();
  });
});

describe("S7d rollups screen", () => {
  it("loads operator rollups (A0)", async () => {
    const s = await setup(operatorWhoami);
    s.controller.openRollups(TRAIL);
    await s.controller.loadOperatorRollups();
    await until(() => {
      const w = home(s.controller).work;
      return w?.kind === "rollups" && w.operator !== null;
    }, "operator rollups never loaded");
    const w = home(s.controller).work;
    if (w?.kind === "rollups") expect(w.operator?.[0]?.metric).toBe("redemptions");
  });
});

describe("S7 settlement export screen", () => {
  it("refuses export when aal is below 2 (A3 client gate)", async () => {
    const s = await setup(staffLowAal);
    s.controller.openSettlement(TRAIL);
    expect(home(s.controller).work?.kind).toBe("settlement");
    await s.controller.exportSettlement();
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "admin.needTotp" } });
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/settlement-export/export"));
    expect(posts).toHaveLength(0);
  });

  it("exports for aal 2 and surfaces path/expiry without logging the signed URL token", async () => {
    const s = await setup(operatorWhoami);
    s.controller.openSettlement(TRAIL);
    s.controller.setSettlementMonth("2026-09");
    await s.controller.exportSettlement();
    await until(() => home(s.controller).notice?.kind === "settlement-exported", "settlement export never completed");
    expect(home(s.controller).notice).toEqual({ kind: "settlement-exported" });
    const w = home(s.controller).work;
    expect(w?.kind).toBe("settlement");
    if (w?.kind === "settlement") {
      expect(w.export?.path).toContain("settlement/trl_demo/");
      expect(w.export?.expiresAt.length).toBeGreaterThan(10);
      expect(w.export?.signedUrl).toContain("token=");
      expect(w.export?.lines[0]?.redemptions).toBe(3);
    }
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/settlement-export/export"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({ trailId: TRAIL, month: "2026-09-01" });
    // Request log must not contain the signed URL token (response body is not re-logged by the client).
    expect(posts[0]!.body).not.toMatch(/fake-signed-token|signedUrl/i);
  });

  it("maps empty month to the empty catalogue key", async () => {
    const s = await setup(operatorWhoami);
    s.controller.openSettlement(TRAIL);
    s.controller.setSettlementMonth("1999-01-01");
    await s.controller.exportSettlement();
    await until(() => home(s.controller).notice?.kind === "error", "empty settlement never surfaced");
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "settlement.empty" } });
  });
});
