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

  it("loads wrong-PIN rotation alarms (A0) for the open facility", async () => {
    const s = await setup();
    s.controller.openCourseQr(FACILITY);
    await s.controller.loadCoursePinAlarms();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("course-qr");
      if (w?.kind === "course-qr") {
        expect(w.alarms).toHaveLength(1);
        expect(w.alarms?.[0]).toMatchObject({
          facilityId: FACILITY,
          localDate: "2026-10-08",
          failures: 30,
          raisedAt: "2026-10-08T15:00:00.000Z",
        });
      }
    }
    const gets = s.w.server.log.filter((r) => r.method === "GET" && r.path.includes("/course-qr/alarms"));
    expect(gets).toHaveLength(1);
  });

  it("loads open static-PIN daily cap alerts (A0) for the open facility", async () => {
    const s = await setup();
    s.controller.openCourseQr(FACILITY);
    await s.controller.loadCourseStaticPinCaps();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("course-qr");
      if (w?.kind === "course-qr") {
        expect(w.capAlerts).toHaveLength(1);
        expect(w.capAlerts?.[0]).toMatchObject({
          facilityId: FACILITY,
          localDate: "2026-10-09",
          count: 25,
          raisedAt: "2026-10-09T16:00:00.000Z",
        });
      }
    }
    const gets = s.w.server.log.filter((r) => r.method === "GET" && r.path.includes("/course-qr/cap-alerts"));
    expect(gets).toHaveLength(1);
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

  it("offline redeem verifies handle + code + nameConfirmed after PIN", async () => {
    const s = await setup();
    s.controller.openOfferRedeem(FACILITY);
    s.controller.setOfferRedeemMode("offline");
    s.controller.selectOfferCode(OFFER_CODE);
    const pending = s.controller.submitOfferRedeemOffline(OFFER_CODE, "Player_One", "123456", true);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for offline offer redeem");
    s.controller.submitPin(PIN);
    await pending;
    expect(home(s.controller).notice).toEqual({ kind: "offer-redeem-ok" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("offer-redeem");
      if (w?.kind === "offer-redeem") {
        expect(w.lastRedeem?.attestationId).toBe("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        expect(w.selectedOfferCodeId).toBe("");
      }
    }
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-offers-redeem/redeem/offline"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({
      facilityId: FACILITY,
      offerCodeId: OFFER_CODE,
      handle: "player_one",
      code: "123456",
      nameConfirmed: true,
    });
    expect(posts[0]!.body).not.toMatch(/7391|derived|pin/i);
  });

  it("offline redeem refuses when nameConfirmed is false before calling the server", async () => {
    const s = await setup();
    s.controller.openOfferRedeem(FACILITY);
    s.controller.setOfferRedeemMode("offline");
    await s.controller.submitOfferRedeemOffline(OFFER_CODE, "player_one", "123456", false);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "offerRedeem.nameUnconfirmed" } });
    expect(home(s.controller).panel).toBeNull();
    const posts = s.w.server.log.filter((r) => r.method === "POST" && r.path.includes("/partner-offers-redeem/"));
    expect(posts).toHaveLength(0);
  });
});

describe("§67 credentials display-note screen", () => {
  const SEEDED_CRED = "11111111-1111-4111-8111-111111111111";

  it("opens, loads the seeded passkey, and PATCHes a display note (A0)", async () => {
    const s = await setup();
    s.controller.openCredentials();
    expect(home(s.controller).work).toMatchObject({ kind: "credentials", rows: null, lastSavedId: null });

    await s.controller.loadCredentials();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") {
        expect(w.rows).toHaveLength(1);
        expect(w.rows?.[0]).toMatchObject({ id: SEEDED_CRED, note: null, revokedAt: null });
      }
    }
    const gets = s.w.server.log.filter((r) => r.method === "GET" && r.path.endsWith("/partner-members/credentials"));
    expect(gets).toHaveLength(1);

    await s.controller.saveCredentialNote(SEEDED_CRED, "  Front desk iPad  ");
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") {
        expect(w.rows?.[0]?.note).toBe("Front desk iPad");
        expect(w.lastSavedId).toBe(SEEDED_CRED);
      }
    }
    expect(home(s.controller).notice).toEqual({ kind: "credential-note-saved" });
    const patches = s.w.server.log.filter((r) => r.method === "PATCH" && r.path.endsWith(`/partner-members/credentials/${SEEDED_CRED}`));
    expect(patches).toHaveLength(1);
    expect(JSON.parse(patches[0]!.body)).toEqual({ note: "Front desk iPad" });
  });

  it("refuses a note longer than 40 characters without calling the server", async () => {
    const s = await setup();
    s.controller.openCredentials();
    await s.controller.loadCredentials();
    await s.controller.saveCredentialNote(SEEDED_CRED, "x".repeat(41));
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "credentials.noteTooLong" } });
    const patches = s.w.server.log.filter((r) => r.method === "PATCH" && r.path.includes("/partner-members/credentials/"));
    expect(patches).toHaveLength(0);
  });
});

describe("§74 credentials revoke (own, A2)", () => {
  const SEEDED_CRED = "11111111-1111-4111-8111-111111111111";
  const EXTRA_CRED = "22222222-2222-4222-8222-222222222222";

  it("refuses to revoke the only active passkey without calling the server", async () => {
    const s = await setup();
    s.controller.openCredentials();
    await s.controller.loadCredentials();
    await s.controller.revokeCredential(SEEDED_CRED);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "credentials.lastActive" } });
    const deletes = s.w.server.log.filter((r) => r.method === "DELETE" && r.path.includes("/partner-members/credentials/"));
    expect(deletes).toHaveLength(0);
    expect(s.w.server.log.some((r) => r.path.endsWith("/reauth/options"))).toBe(false);
  });

  it("revokes a second passkey after reauth + A2 PIN, then reloads the list", async () => {
    const s = await setup();
    s.w.server.seedExtraCredential(EXTRA_CRED);
    s.controller.openCredentials();
    await s.controller.loadCredentials();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") expect(w.rows).toHaveLength(2);
    }

    const pending = s.controller.revokeCredential(EXTRA_CRED);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for credential revoke");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "credential-revoked" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") {
        expect(w.rows).toHaveLength(1);
        expect(w.rows?.[0]?.id).toBe(SEEDED_CRED);
      }
    }
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth"))).toBe(true);
    const pinPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/step-up/pin"));
    expect(pinPosts).toHaveLength(1);
    expect(JSON.parse(pinPosts[0]!.body).derived).not.toContain(PIN);
    const deletes = s.w.server.log.filter((r) => r.method === "DELETE" && r.path.endsWith(`/partner-members/credentials/${EXTRA_CRED}`));
    expect(deletes).toHaveLength(1);
  });
});
