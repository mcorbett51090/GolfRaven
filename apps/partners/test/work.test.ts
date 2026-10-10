/**
 * S7b/S7c work screens through the controller: open attest / course-QR / stock / hand-over, requirePin then the action, and the request body never carries the PIN's digits.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController, type AppState, type SignedInState } from "../src/app/controller";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { API_BASE, makeWorld } from "./support/world";

const PIN = "7391";
const FACILITY = "44444444-4444-4444-8444-444444444444";
const TOKEN = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

async function setup() {
  const w = makeWorld();
  await w.server.seedPin(PIN);
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

describe("S7b attest screen", () => {
  it("opens from home, asks for a PIN on submit, then posts attest without the PIN digits", async () => {
    const s = await setup();
    s.controller.openAttest(FACILITY);
    expect(home(s.controller).work?.kind).toBe("attest");
    expect(home(s.controller).work).toMatchObject({ facilityId: FACILITY, mode: "online" });

    const pending = s.controller.submitOnlineAttest(TOKEN);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened");
    s.controller.submitPin(PIN);
    await pending;

    const st = home(s.controller);
    expect(st.notice).toEqual({ kind: "attest-ok" });
    expect(st.work?.kind === "attest" && st.work.lastResult).toEqual({ attestationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", held: false });
    expect(st.panel).toBeNull();

    const attestPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-attest/attest"));
    expect(attestPosts).toHaveLength(1);
    expect(JSON.parse(attestPosts[0]!.body)).toEqual({ facilityId: FACILITY, kind: "presence", token: TOKEN });
    expect(attestPosts[0]!.body).not.toMatch(/7391|derived|pin/i);
    const pinPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/step-up/pin"));
    expect(pinPosts).toHaveLength(1);
    expect(JSON.parse(pinPosts[0]!.body)).toEqual({ derived: expect.any(String) });
    expect(JSON.parse(pinPosts[0]!.body).derived).not.toContain(PIN);
  });

  it("offline attest verifies handle + code after a PIN", async () => {
    const s = await setup();
    s.controller.openAttest(FACILITY);
    s.controller.setAttestMode("offline");
    s.controller.setAttestKind("marker_purchase");
    const pending = s.controller.submitOfflineAttest("player_one", "123456");
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened");
    s.controller.submitPin(PIN);
    await pending;
    expect(home(s.controller).notice).toEqual({ kind: "attest-ok" });
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.includes("/partner-attest/attest/offline"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({ facilityId: FACILITY, kind: "marker_purchase", handle: "player_one", code: "123456" });
  });
});

describe("S7b course-QR screen", () => {
  it("loads today's PIN (A0) and mints a token only after a PIN grant (A1)", async () => {
    const s = await setup();
    s.controller.openCourseQr(FACILITY);
    expect(home(s.controller).work?.kind).toBe("course-qr");

    await s.controller.loadCoursePin();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("course-qr");
      if (w?.kind === "course-qr") expect(w.pin?.pin).toBe("4242");
    }

    const pending = s.controller.mintToken();
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for mint");
    s.controller.submitPin(PIN);
    await pending;
    expect(home(s.controller).notice).toEqual({ kind: "token-minted" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("course-qr");
      if (w?.kind === "course-qr") expect(w.sale?.nonceHash).toBe("a".repeat(64));
    }
    const mintBody = s.w.server.log.filter((r) => r.path.endsWith("/course-qr/tokens")).map((r) => r.body);
    expect(mintBody.some((b) => b.includes(PIN))).toBe(false);
  });
});

describe("S7c stock screen", () => {
  it("loads stock (A0) and records a move only after a PIN grant (A1)", async () => {
    const s = await setup();
    s.controller.openStock(FACILITY);
    expect(home(s.controller).work?.kind).toBe("stock");

    await s.controller.loadStock();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("stock");
      if (w?.kind === "stock") expect(w.rows?.[0]?.trailId).toBe("trl_demo");
    }

    const pending = s.controller.submitStockMove("trl_demo", "delivered", 2, null);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for stock move");
    s.controller.submitPin(PIN);
    await pending;
    expect(home(s.controller).notice).toEqual({ kind: "stock-moved" });
    const movePosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/stock-admin/stock/move"));
    expect(movePosts).toHaveLength(1);
    expect(JSON.parse(movePosts[0]!.body)).toEqual({ facilityId: FACILITY, trailId: "trl_demo", kind: "delivered", qty: 2 });
    expect(movePosts[0]!.body).not.toMatch(/7391|derived|pin/i);
  });
});

describe("S7c hand-over screen", () => {
  it("mints a gr_ho_ token after PIN and redeems with staff_scan after PIN", async () => {
    const s = await setup();
    s.controller.openHandover(FACILITY);
    expect(home(s.controller).work?.kind).toBe("handover");

    await s.controller.loadCollectQueue();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("handover");
      if (w?.kind === "handover") expect(w.queue?.[0]?.playerHandle).toBe("player_one");
    }

    const ent = "51000000-0000-0000-0000-000000003601";
    const mintPending = s.controller.mintHandover(ent);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for mint");
    s.controller.submitPin(PIN);
    await mintPending;
    expect(home(s.controller).notice).toEqual({ kind: "handover-minted" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("handover");
      if (w?.kind === "handover") expect(w.minted?.token.startsWith("gr_ho_")).toBe(true);
    }

    s.controller.dismissHandoverMint();
    const redeemPending = s.controller.submitRedeem(ent, TOKEN);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for redeem");
    s.controller.submitPin(PIN);
    await redeemPending;
    expect(home(s.controller).notice).toEqual({ kind: "redeem-ok" });
    const redeemPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-entitlements/redeem"));
    expect(redeemPosts).toHaveLength(1);
    expect(JSON.parse(redeemPosts[0]!.body)).toEqual({
      facilityId: FACILITY,
      entitlementId: ent,
      method: "staff_scan",
      credential: TOKEN,
    });
    expect(redeemPosts[0]!.body).not.toMatch(/7391|derived|pin/i);
  });
});

describe("S7 offer-redeem screen", () => {
  const OFFER_CODE = "71000000-0000-0000-0000-000000007101";

  it("loads the issued-code queue and redeems via staff_scan after PIN", async () => {
    const s = await setup();
    s.controller.openOfferRedeem(FACILITY);
    expect(home(s.controller).work?.kind).toBe("offer-redeem");

    await s.controller.loadOffersQueue();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("offer-redeem");
      if (w?.kind === "offer-redeem") expect(w.queue?.[0]?.playerHandle).toBe("player_one");
    }

    s.controller.selectOfferCode(OFFER_CODE);
    {
      const w = home(s.controller).work;
      if (w?.kind === "offer-redeem") expect(w.selectedOfferCodeId).toBe(OFFER_CODE);
    }

    const redeemPending = s.controller.submitOfferRedeem(OFFER_CODE, TOKEN);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for offer redeem");
    s.controller.submitPin(PIN);
    await redeemPending;
    expect(home(s.controller).notice).toEqual({ kind: "offer-redeem-ok" });
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-offers-redeem/redeem"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({
      facilityId: FACILITY,
      offerCodeId: OFFER_CODE,
      method: "staff_scan",
      credential: TOKEN,
    });
    expect(posts[0]!.body).not.toMatch(/7391|derived|pin/i);
  });
});
