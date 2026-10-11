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

async function until(cond: () => boolean, label: string, ms = 2000): Promise<void> {
  const steps = Math.max(1, Math.ceil(ms / 5));
  for (let i = 0; i < steps; i += 1) {
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

describe("§75 credentials add (second passkey, A2)", () => {
  it("refuses when five active passkeys are already held, without calling the server", async () => {
    const s = await setup();
    for (let i = 2; i <= 5; i += 1) {
      s.w.server.seedExtraCredential(`${i}${i}${i}${i}${i}${i}${i}${i}-2222-4222-8222-22222222222${i}`);
    }
    s.controller.openCredentials();
    await s.controller.loadCredentials();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") expect(w.rows).toHaveLength(5);
    }
    await s.controller.addCredential();
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "credentials.tooMany" } });
    expect(s.w.server.log.some((r) => r.path.endsWith("/reauth/options"))).toBe(false);
    expect(s.w.server.log.some((r) => r.path.endsWith("/partner-members/credentials/options"))).toBe(false);
  });

  it("adds a second passkey after reauth + two A2 PIN grants (options then register)", async () => {
    const s = await setup();
    s.controller.openCredentials();
    await s.controller.loadCredentials();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") expect(w.rows).toHaveLength(1);
    }

    // auto-submit each idle A2 prompt once (two grants: options then register); avoids racing the busy first panel
    let armed = true;
    const stop = s.controller.subscribe((st) => {
      if (!armed || st.screen !== "signed-in") return;
      const p = st.panel;
      if (p?.kind === "pin-prompt" && p.actionClass === "A2" && p.busy === false) {
        armed = false;
        queueMicrotask(() => {
          s.controller.submitPin(PIN);
          armed = true;
        });
      }
    });
    try {
      await s.controller.addCredential();
    } finally {
      stop();
    }

    expect(home(s.controller).notice).toEqual({ kind: "credential-added" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") expect(w.rows).toHaveLength(2);
    }
    expect(s.w.auth.created).toHaveLength(1);
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth"))).toBe(true);
    const pinPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/step-up/pin"));
    expect(pinPosts).toHaveLength(2);
    for (const p of pinPosts) expect(JSON.parse(p.body).derived).not.toContain(PIN);
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/partner-members/credentials/options"))).toBe(true);
    const registers = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-members/credentials"));
    expect(registers).toHaveLength(1);
    expect(JSON.parse(registers[0]!.body).challengeToken).toMatch(/^[A-Za-z0-9_-]+\.\d+\.[A-Za-z0-9_-]+$/);
    expect(registers[0]!.body).not.toMatch(/7391/);
  });
});

describe("§81 team credentials under reach (manager)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const OTHER_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const OTHER_CRED = "33333333-3333-4333-8333-333333333301";
  const OTHER_NOTICE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const managerWhoami = {
    aal: 1,
    requiredAal: 1,
    isAdmin: false,
    memberships: [{ orgId: ORG, role: "manager", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupManager() {
    const w = makeWorld({ whoami: managerWhoami });
    await w.server.seedPin(PIN);
    w.server.seedMember({ userId: OTHER_USER, orgId: ORG, role: "staff", facilityId: FACILITY });
    w.server.seedCredentialForUser(OTHER_USER, OTHER_CRED);
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("§94 loadMembers also lists unacked credential-add notices under reach (never the actor's own)", async () => {
    const s = await setupManager();
    s.w.server.seedCredentialAddNotice({
      noticeId: OTHER_NOTICE,
      credentialId: OTHER_CRED,
      subjectUserId: OTHER_USER,
      label: "2030-01-01 / unknown",
    });
    // Own notice (subject = signed-in manager) must not appear on the reach list.
    s.w.server.seedCredentialAddNotice({
      noticeId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      credentialId: "44444444-4444-4444-8444-444444444401",
      label: "own-should-hide",
    });
    s.controller.openMembers();
    await s.controller.loadMembers();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") {
        expect(w.credentialAddNotices).toEqual([
          {
            noticeId: OTHER_NOTICE,
            credentialId: OTHER_CRED,
            label: "2030-01-01 / unknown",
            createdAt: "2026-06-01T12:00:00.000Z",
            credentialRevokedAt: null,
            subjectUserId: OTHER_USER,
          },
        ]);
      }
    }
  });

  it("opens roster, loads members, then lists and notes another member's passkey", async () => {
    const s = await setupManager();
    s.controller.openMembers();
    expect(home(s.controller).work).toMatchObject({ kind: "members", rows: null, credentialAddNotices: null });

    await s.controller.loadMembers();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") {
        expect(w.rows).toHaveLength(1);
        expect(w.rows?.[0]).toMatchObject({ userId: OTHER_USER, role: "staff", orgId: ORG });
        expect(w.credentialAddNotices).toEqual([]);
      }
    }
    const memberGets = s.w.server.log.filter((r) => r.method === "GET" && r.path.endsWith("/partner-members/members"));
    expect(memberGets).toHaveLength(1);
    const noticeGets = s.w.server.log.filter((r) => r.method === "GET" && r.path.endsWith("/partner-members/credentials/notices/reach"));
    expect(noticeGets).toHaveLength(1);

    s.controller.openMemberCredentials(OTHER_USER);
    expect(home(s.controller).work).toMatchObject({ kind: "credentials", targetUserId: OTHER_USER, rows: null });

    await s.controller.loadCredentials();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") {
        expect(w.rows).toHaveLength(1);
        expect(w.rows?.[0]).toMatchObject({ id: OTHER_CRED, note: null });
      }
    }
    const credGets = s.w.server.log.filter((r) => r.method === "GET" && r.path.endsWith("/partner-members/credentials"));
    expect(credGets.some((r) => r.search === `?userId=${OTHER_USER}`)).toBe(true);

    await s.controller.saveCredentialNote(OTHER_CRED, "Shop floor");
    expect(home(s.controller).notice).toEqual({ kind: "credential-note-saved" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") expect(w.rows?.[0]?.note).toBe("Shop floor");
    }
    const patches = s.w.server.log.filter((r) => r.method === "PATCH" && r.path.endsWith(`/partner-members/credentials/${OTHER_CRED}`));
    expect(patches).toHaveLength(1);
    expect(JSON.parse(patches[0]!.body)).toEqual({ note: "Shop floor" });
  });

  it("revokes another member's only passkey after reauth + A2 PIN (no last-active refuse)", async () => {
    const s = await setupManager();
    s.controller.openMemberCredentials(OTHER_USER);
    await s.controller.loadCredentials();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") expect(w.rows).toHaveLength(1);
    }

    const pending = s.controller.revokeCredential(OTHER_CRED);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for team credential revoke");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "credential-revoked" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("credentials");
      if (w?.kind === "credentials") expect(w.rows).toHaveLength(0);
    }
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    const pinPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/step-up/pin"));
    expect(pinPosts).toHaveLength(1);
    expect(JSON.parse(pinPosts[0]!.body).derived).not.toContain(PIN);
    const deletes = s.w.server.log.filter((r) => r.method === "DELETE" && r.path.endsWith(`/partner-members/credentials/${OTHER_CRED}`));
    expect(deletes).toHaveLength(1);
    expect(s.w.server.log.some((r) => r.path.endsWith("/partner-members/credentials/options"))).toBe(false);
  });

  it("staff whoami: openMembers is a no-op and never GETs members", async () => {
    const s = await setup();
    s.controller.openMembers();
    expect(home(s.controller).work).toBeNull();
    expect(s.w.server.log.some((r) => r.path.endsWith("/partner-members/members"))).toBe(false);
  });
});

describe("§82 member PIN reset under reach (manager, A2)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const OTHER_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const managerWhoami = {
    aal: 1,
    requiredAal: 1,
    isAdmin: false,
    memberships: [{ orgId: ORG, role: "manager", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupManager() {
    const w = makeWorld({ whoami: managerWhoami });
    await w.server.seedPin(PIN);
    w.server.seedMember({ userId: OTHER_USER, orgId: ORG, role: "staff", facilityId: FACILITY });
    await w.server.seedPin("2468", { userId: OTHER_USER, locked: true, failures: 5 });
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("resets another member's locked PIN after reauth + A2 PIN", async () => {
    const s = await setupManager();
    s.controller.openMembers();
    await s.controller.loadMembers();

    const pending = s.controller.resetMemberPin(OTHER_USER);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for member pin-reset");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "member-pin-reset" });
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    const pinPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/step-up/pin"));
    expect(pinPosts).toHaveLength(1);
    expect(JSON.parse(pinPosts[0]!.body).derived).not.toContain(PIN);
    const resets = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/members/${OTHER_USER}/pin-reset`));
    expect(resets).toHaveLength(1);
    expect(JSON.parse(resets[0]!.body)).toEqual({});
    const record = s.w.server.pinRecord(OTHER_USER);
    expect(record).toMatchObject({ locked: false, failures: 0, mustChange: true });
    expect(resets[0]!.body).not.toMatch(/7391|2468/);
  });

  it("refuses to reset one's own PIN without calling the server", async () => {
    const s = await setupManager();
    const selfId = home(s.controller).session.userId;
    s.controller.openMembers();
    await s.controller.loadMembers();
    await s.controller.resetMemberPin(selfId);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.pinSelf" } });
    expect(s.w.server.log.some((r) => r.path.includes("/pin-reset"))).toBe(false);
    expect(s.w.server.log.some((r) => r.path.endsWith("/reauth/options"))).toBe(false);
  });

  it("surfaces pin_not_set when the target has no PIN", async () => {
    const s = await setupManager();
    const unsetUser = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    s.w.server.seedMember({ userId: unsetUser, orgId: ORG, role: "staff", facilityId: FACILITY });
    s.controller.openMembers();
    await s.controller.loadMembers();

    const pending = s.controller.resetMemberPin(unsetUser);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for unset pin-reset");
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.pinNotSet" } });
    const resets = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/members/${unsetUser}/pin-reset`));
    expect(resets).toHaveLength(1);
  });
});

describe("§83 member recover under reach (manager, A2)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const OTHER_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const OTHER_CRED = "33333333-3333-4333-8333-333333333301";
  const managerWhoami = {
    aal: 1,
    requiredAal: 1,
    isAdmin: false,
    memberships: [{ orgId: ORG, role: "manager", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupManager() {
    const w = makeWorld({ whoami: managerWhoami });
    await w.server.seedPin(PIN);
    w.server.seedMember({ userId: OTHER_USER, orgId: ORG, role: "staff", facilityId: FACILITY });
    w.server.seedCredentialForUser(OTHER_USER, OTHER_CRED);
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("recovers another member after reauth + A2 PIN and holds the one-time token until dismiss", async () => {
    const s = await setupManager();
    s.controller.openMembers();
    await s.controller.loadMembers();

    const pending = s.controller.recoverMember(OTHER_USER);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for member recover");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "member-recovered" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") {
        expect(w.recovered).not.toBeNull();
        expect(w.recovered?.token).toMatch(/^gr_enr_[A-Za-z0-9_-]{43}$/);
        expect(w.recovered?.enrolUrl).toContain(`/enrol#${w.recovered?.token}`);
      }
    }
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    const recovers = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/members/${OTHER_USER}/recover`));
    expect(recovers).toHaveLength(1);
    expect(JSON.parse(recovers[0]!.body)).toEqual({});
    expect(recovers[0]!.body).not.toMatch(/gr_enr_|7391/);

    s.controller.dismissMemberRecover();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") expect(w.recovered).toBeNull();
    }
    expect(home(s.controller).notice).toBeNull();
  });

  it("refuses to recover oneself without calling the server", async () => {
    const s = await setupManager();
    const selfId = home(s.controller).session.userId;
    s.controller.openMembers();
    await s.controller.loadMembers();
    await s.controller.recoverMember(selfId);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.recoverSelf" } });
    expect(s.w.server.log.some((r) => r.path.includes("/recover"))).toBe(false);
  });

  it("surfaces no_email when the target has no email", async () => {
    const s = await setupManager();
    const noMail = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    s.w.server.seedMember({ userId: noMail, orgId: ORG, role: "staff", facilityId: FACILITY, email: null });
    s.controller.openMembers();
    await s.controller.loadMembers();

    const pending = s.controller.recoverMember(noMail);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for no_email recover");
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.noEmail" } });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") expect(w.recovered).toBeNull();
    }
  });
});

describe("§84 member revoke under reach (manager, A2)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const OTHER_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const managerWhoami = {
    aal: 1,
    requiredAal: 1,
    isAdmin: false,
    memberships: [{ orgId: ORG, role: "manager", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupManager() {
    const w = makeWorld({ whoami: managerWhoami });
    await w.server.seedPin(PIN);
    w.server.seedMember({ userId: OTHER_USER, orgId: ORG, role: "staff", facilityId: FACILITY });
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("ends one membership after reauth + A2 PIN and reloads the roster", async () => {
    const s = await setupManager();
    s.controller.openMembers();
    await s.controller.loadMembers();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") expect(w.rows).toHaveLength(1);
    }

    const pending = s.controller.revokeMember(OTHER_USER, ORG);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for member revoke");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "member-revoked" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") expect(w.rows).toHaveLength(0);
    }
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    const revokes = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/members/${OTHER_USER}/revoke`));
    expect(revokes).toHaveLength(1);
    expect(JSON.parse(revokes[0]!.body)).toEqual({ orgId: ORG });
    expect(revokes[0]!.body).not.toMatch(/7391/);
  });

  it("refuses to revoke one's own membership without calling the server", async () => {
    const s = await setupManager();
    const selfId = home(s.controller).session.userId;
    s.controller.openMembers();
    await s.controller.loadMembers();
    await s.controller.revokeMember(selfId, ORG);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.revokeSelf" } });
    expect(s.w.server.log.some((r) => r.path.endsWith("/revoke") && r.path.includes("/members/"))).toBe(false);
  });
});

describe("§85 org sessions revoke-all (manager, A2)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const OTHER_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const managerWhoami = {
    aal: 1,
    requiredAal: 1,
    isAdmin: false,
    memberships: [{ orgId: ORG, role: "manager", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupManager() {
    const w = makeWorld({ whoami: managerWhoami });
    await w.server.seedPin(PIN);
    w.server.seedMember({ userId: OTHER_USER, orgId: ORG, role: "staff", facilityId: FACILITY });
    w.server.seedCredentialForUser(OTHER_USER);
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("ends org sessions after reauth + A2 PIN and keeps the counts (no roster reload)", async () => {
    const s = await setupManager();
    s.controller.openMembers();
    await s.controller.loadMembers();

    const pending = s.controller.revokeAllOrgSessions(ORG);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for org revoke-all");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "org-revoke-all" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") {
        expect(w.lastRevokeAll).toEqual({ orgId: ORG, sessions: 2, credentials: 0 });
        expect(w.rows).toHaveLength(1);
      }
    }
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    const calls = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/orgs/${ORG}/sessions/revoke-all`));
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0]!.body)).toEqual({});
    expect(calls[0]!.body).not.toMatch(/7391/);
  });

  it("sends normalised createdAfter and counts credential revokes", async () => {
    const s = await setupManager();
    s.controller.openMembers();
    s.controller.setOrgRevokeCreatedAfter("2020-01-01T00:00:00Z");
    const pending = s.controller.revokeAllOrgSessions(ORG);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for revoke-all with createdAfter");
    s.controller.submitPin(PIN);
    await pending;

    const calls = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/orgs/${ORG}/sessions/revoke-all`));
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0]!.body)).toEqual({ createdAfter: "2020-01-01T00:00:00.000Z" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") expect(w.lastRevokeAll?.credentials).toBe(1);
    }
  });

  it("refuses a bad createdAfter without calling the server", async () => {
    const s = await setupManager();
    s.controller.openMembers();
    s.controller.setOrgRevokeCreatedAfter("yesterday");
    await s.controller.revokeAllOrgSessions(ORG);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.createdAfterInvalid" } });
    expect(s.w.server.log.some((r) => r.path.includes("/sessions/revoke-all"))).toBe(false);
  });
});

describe("§86 member TOTP reset under reach (admin, A3)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const OTHER_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const adminWhoami = {
    aal: 2,
    requiredAal: 2,
    isAdmin: true,
    memberships: [{ orgId: ORG, role: "operator", facilityIds: [FACILITY], trailIds: [] }],
  };
  const adminLowAal = {
    aal: 1,
    requiredAal: 2,
    isAdmin: true,
    memberships: [{ orgId: ORG, role: "operator", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupAdmin(whoami: typeof adminWhoami) {
    const w = makeWorld({ whoami });
    await w.server.seedPin(PIN);
    w.server.seedMember({ userId: OTHER_USER, orgId: ORG, role: "operator", facilityId: FACILITY });
    w.server.seedMemberTotp(OTHER_USER);
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("resets an operator's TOTP when the admin already holds aal 2 (no PIN prompt)", async () => {
    const s = await setupAdmin(adminWhoami);
    s.controller.openMembers();
    await s.controller.loadMembers();
    await s.controller.resetMemberTotp(OTHER_USER);
    expect(home(s.controller).notice).toEqual({ kind: "member-totp-reset" });
    expect(home(s.controller).panel).toBeNull();
    const calls = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/members/${OTHER_USER}/totp-reset`));
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0]!.body)).toEqual({});
  });

  it("refuses without aal 2 and does not call the server", async () => {
    const s = await setupAdmin(adminLowAal);
    s.controller.openMembers();
    await s.controller.resetMemberTotp(OTHER_USER);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.needTotp" } });
    expect(s.w.server.log.some((r) => r.path.includes("/totp-reset"))).toBe(false);
  });

  it("refuses to reset one's own authenticator without calling the server", async () => {
    const s = await setupAdmin(adminWhoami);
    const selfId = home(s.controller).session.userId;
    s.controller.openMembers();
    await s.controller.resetMemberTotp(selfId);
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.totpSelf" } });
    expect(s.w.server.log.some((r) => r.path.includes("/totp-reset"))).toBe(false);
  });
});

describe("§87 admin enrolment issue (admin, A3)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const OTHER_ADMIN = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const adminWhoami = {
    aal: 2,
    requiredAal: 2,
    isAdmin: true,
    memberships: [{ orgId: ORG, role: "operator", facilityIds: [FACILITY], trailIds: [] }],
  };
  const adminLowAal = {
    aal: 1,
    requiredAal: 2,
    isAdmin: true,
    memberships: [{ orgId: ORG, role: "operator", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupAdmin(whoami: typeof adminWhoami) {
    const w = makeWorld({ whoami });
    await w.server.seedPin(PIN);
    w.server.seedAdminUser(OTHER_ADMIN);
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("issues a one-time enrolment link when the admin holds aal 2", async () => {
    const s = await setupAdmin(adminWhoami);
    s.controller.openMembers();
    s.controller.setAdminEnrolUserId(OTHER_ADMIN);
    await s.controller.issueAdminEnrolment();
    expect(home(s.controller).notice).toEqual({ kind: "admin-enrolment" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("members");
      if (w?.kind === "members") {
        expect(w.adminEnrolment).not.toBeNull();
        expect(w.adminEnrolment?.token.startsWith("gr_enr_")).toBe(true);
        expect(w.adminEnrolment?.enrolUrl).toContain("#gr_enr_");
      }
    }
    const calls = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-members/admin/enrolments"));
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0]!.body)).toEqual({ userId: OTHER_ADMIN });
    s.controller.dismissAdminEnrolment();
    {
      const w = home(s.controller).work;
      if (w?.kind === "members") expect(w.adminEnrolment).toBeNull();
    }
  });

  it("refuses without aal 2 and does not call the server", async () => {
    const s = await setupAdmin(adminLowAal);
    s.controller.openMembers();
    s.controller.setAdminEnrolUserId(OTHER_ADMIN);
    await s.controller.issueAdminEnrolment();
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.needTotp" } });
    expect(s.w.server.log.some((r) => r.path.includes("/admin/enrolments"))).toBe(false);
  });

  it("refuses issuing for oneself without calling the server", async () => {
    const s = await setupAdmin(adminWhoami);
    const selfId = home(s.controller).session.userId;
    s.controller.openMembers();
    s.controller.setAdminEnrolUserId(selfId);
    await s.controller.issueAdminEnrolment();
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "members.adminEnrolSelf" } });
    expect(s.w.server.log.some((r) => r.path.includes("/admin/enrolments"))).toBe(false);
  });
});

describe("§88 invites manage UI (manager, A0/A2)", () => {
  const ORG = "33333333-3333-4333-8333-333333333333";
  const INVITEE = "new.staff@example.test";
  const managerWhoami = {
    aal: 1,
    requiredAal: 1,
    isAdmin: false,
    memberships: [{ orgId: ORG, role: "manager", facilityIds: [FACILITY], trailIds: [] }],
  };

  async function setupManager() {
    const w = makeWorld({ whoami: managerWhoami });
    await w.server.seedPin(PIN);
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const states: AppState[] = [];
    controller.subscribe((s) => states.push(s));
    await controller.signIn();
    return { w, api, controller, states };
  }

  it("staff whoami: openInvites is a no-op", async () => {
    const s = await setup();
    s.controller.openInvites();
    expect(home(s.controller).work).toBeNull();
    expect(s.w.server.log.some((r) => r.path.includes("/partner-invites/invites"))).toBe(false);
  });

  it("lists pending invites (A0) and creates one after reauth + A2 PIN (show-once)", async () => {
    const s = await setupManager();
    s.controller.openInvites();
    expect(home(s.controller).work).toMatchObject({ kind: "invites", orgIdDraft: ORG, rows: null, created: null });

    await s.controller.loadInvites();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("invites");
      if (w?.kind === "invites") expect(w.rows).toEqual([]);
    }
    expect(s.w.server.log.some((r) => r.method === "GET" && r.path.endsWith("/partner-invites/invites") && r.search === `?orgId=${ORG}`)).toBe(true);

    s.controller.setInviteEmail(INVITEE);
    s.controller.setInviteRole("staff");
    const pending = s.controller.createInvite();
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for invite create");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "invite-created" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("invites");
      if (w?.kind === "invites") {
        expect(w.created).not.toBeNull();
        expect(w.created?.token.startsWith("gr_inv_")).toBe(true);
        expect(w.created?.inviteUrl).toContain("#gr_inv_");
        expect(w.emailDraft).toBe("");
      }
    }
    const creates = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-invites/invites"));
    expect(creates).toHaveLength(1);
    expect(JSON.parse(creates[0]!.body)).toEqual({ orgId: ORG, role: "staff", email: INVITEE });
    expect(creates[0]!.body).not.toMatch(/7391/);
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    const pinPosts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/step-up/pin"));
    expect(pinPosts).toHaveLength(1);
    expect(JSON.parse(pinPosts[0]!.body).derived).not.toContain(PIN);

    s.controller.dismissInviteCreated();
    {
      const w = home(s.controller).work;
      if (w?.kind === "invites") expect(w.created).toBeNull();
    }

    await s.controller.loadInvites();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("invites");
      if (w?.kind === "invites") {
        expect(w.rows).toHaveLength(1);
        expect(w.rows?.[0]).toMatchObject({ inviteeEmail: INVITEE, role: "staff", orgId: ORG, revokedAt: null });
      }
    }
  });

  it("revokes a pending invite after reauth + A2 PIN", async () => {
    const s = await setupManager();
    const { inviteId } = s.w.server.addInvite({ email: INVITEE, orgId: ORG, role: "staff" });
    s.controller.openInvites();
    await s.controller.loadInvites();
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("invites");
      if (w?.kind === "invites") expect(w.rows?.some((r) => r.id === inviteId)).toBe(true);
    }

    const pending = s.controller.revokeInvite(inviteId);
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for invite revoke");
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "invite-revoked" });
    {
      const w = home(s.controller).work;
      expect(w?.kind).toBe("invites");
      if (w?.kind === "invites") {
        const row = w.rows?.find((r) => r.id === inviteId);
        expect(row?.revokedAt).not.toBeNull();
      }
    }
    const deletes = s.w.server.log.filter((r) => r.method === "DELETE" && r.path.endsWith(`/partner-invites/invites/${inviteId}`));
    expect(deletes).toHaveLength(1);
  });

  it("refuses create with a bad email without calling the server", async () => {
    const s = await setupManager();
    s.controller.openInvites();
    s.controller.setInviteEmail("not-an-email");
    await s.controller.createInvite();
    expect(home(s.controller).notice).toEqual({ kind: "error", message: { key: "invites.emailInvalid" } });
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/partner-invites/invites"))).toBe(false);
  });
});

describe("§89 branch E invite accept (signed-in, A2)", () => {
  const OTHER_ORG = "55555555-5555-4555-8555-555555555555";
  /** Matches the fake signed-in user's mailbox so branch E email check passes. */
  const SELF_EMAIL = "staff@partners.example.test";

  async function setupSignedIn() {
    const w = makeWorld();
    await w.server.seedPin(PIN);
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    await controller.signIn();
    return { w, api, controller };
  }

  it("holds a gr_inv_ from holdInviteAccept and joins after reauth + A2 PIN", async () => {
    const s = await setupSignedIn();
    const { token } = s.w.server.addInvite({ email: SELF_EMAIL, orgId: OTHER_ORG, role: "staff" });
    expect(s.controller.holdInviteAccept(token)).toBe(true);
    expect(home(s.controller).pendingInviteAccept).toBe(true);
    expect(home(s.controller).notice).toEqual({ kind: "invite-accept-pending" });

    const pending = s.controller.acceptInvite();
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for branch E");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).notice).toEqual({ kind: "invite-accepted" });
    expect(home(s.controller).pendingInviteAccept).toBe(false);
    expect(s.controller.hasPendingInviteAccept()).toBe(false);
    const accepts = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-invites/invites/accept"));
    expect(accepts).toHaveLength(1);
    expect(JSON.parse(accepts[0]!.body)).toEqual({ token });
    expect(accepts[0]!.body).not.toMatch(/7391/);
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
  });

  it("dismiss clears the pending invite without calling the server", async () => {
    const s = await setupSignedIn();
    const { token } = s.w.server.addInvite({ email: SELF_EMAIL, orgId: OTHER_ORG, role: "staff" });
    s.controller.holdInviteAccept(token);
    s.controller.dismissInviteAccept();
    expect(home(s.controller).pendingInviteAccept).toBe(false);
    expect(s.controller.hasPendingInviteAccept()).toBe(false);
    expect(s.w.server.log.some((r) => r.path.endsWith("/invites/accept"))).toBe(false);
  });

  it("refuses to hold an enrolment token", async () => {
    const s = await setupSignedIn();
    const { token } = s.w.server.addEnrolment({ email: SELF_EMAIL });
    expect(s.controller.holdInviteAccept(token)).toBe(false);
    expect(home(s.controller).pendingInviteAccept).toBe(false);
  });
});
