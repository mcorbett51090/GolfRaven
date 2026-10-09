/**
 * S7b work screens through the controller: open attest / course-QR, requirePin then the action, and the request body never carries the PIN's digits.
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
