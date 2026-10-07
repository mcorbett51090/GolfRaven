/**
 * Page lifecycle (MEDIUM-1): `pagehide` ends the session, `pageshow` with `persisted` forces signed-out. The Playwright suite proves the same against
 * Chromium's real back/forward cache; these cells pin the handler logic without a browser.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController } from "../src/app/controller";
import { installPageLifecycle } from "../src/app/lifecycle";
import { API_BASE, makeWorld } from "./support/world";

function setup() {
  const w = makeWorld();
  const seen: Array<{ url: string; keepalive: boolean | undefined; authorization: string | null }> = [];
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push({ url: String(input), keepalive: init?.keepalive, authorization: new Headers(init?.headers).get("authorization") });
    return w.fetch(input, init);
  }) as typeof fetch;
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: f });
  const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
  const target = new EventTarget();
  installPageLifecycle(target, api, controller);
  const pageshow = (persisted: boolean) => target.dispatchEvent(Object.assign(new Event("pageshow"), { persisted }));
  return { w, api, controller, target, seen, pageshow };
}
const tick = (ms = 30) => new Promise((r) => setTimeout(r, ms));

describe("pagehide", () => {
  it("wipes the token and shows signed-out at once, then revokes the session with a KEEPALIVE sign-out carrying the old token", async () => {
    const { w, api, controller, target, seen } = setup();
    await controller.signIn();
    const token = w.server.issuedTokens[0]!;
    seen.length = 0;
    target.dispatchEvent(new Event("pagehide"));
    expect(api.hasSession()).toBe(false);
    expect(controller.getState().screen).toBe("signed-out");
    await tick();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({ url: `${API_BASE}/partner-session/sign-out`, keepalive: true, authorization: `Bearer ${token}` });
    expect(w.server.state.revokedSessions.size).toBe(1);
  });

  it("signed out already: nothing is sent", async () => {
    const { target, seen } = setup();
    target.dispatchEvent(new Event("pagehide"));
    await tick();
    expect(seen).toEqual([]);
  });

  it("during a sign-in: the sign-in is cancelled", async () => {
    const { target, controller } = setup();
    const p = controller.signIn();
    target.dispatchEvent(new Event("pagehide"));
    await p;
    expect(controller.getState().screen).toBe("signed-out");
  });
});

describe("pageshow", () => {
  it("a bfcache restore (persisted) of a page that still believes it is signed in forces signed-out and drops the token", async () => {
    const { api, controller, pageshow, w } = setup();
    await controller.signIn(); // no pagehide ran: the restored page is exactly as it was
    expect(controller.getState().screen).toBe("signed-in");
    pageshow(true);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "expired" } });
    expect(api.hasSession()).toBe(false);
    await tick();
    expect(w.server.state.revokedSessions.size).toBe(1); // and the session the restored page was holding is revoked
  });

  it("an ordinary pageshow (not persisted: the first load) changes nothing", async () => {
    const { controller, pageshow } = setup();
    await controller.signIn();
    pageshow(false);
    expect(controller.getState().screen).toBe("signed-in");
  });
});

describe("main.ts installs it", () => {
  it("main.ts wires installPageLifecycle to window with the client and the controller", () => {
    const main = readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
    expect(main).toMatch(/installPageLifecycle\(window,\s*api,\s*controller\)/);
  });
});
