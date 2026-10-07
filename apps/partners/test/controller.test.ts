import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController, type AppState } from "../src/app/controller";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { API_BASE, makeWorld, type World } from "./support/world";

function setup(over: Parameters<typeof makeWorld>[0] = {}, wrapFetch?: (f: typeof fetch, w: World) => typeof fetch) {
  const w = makeWorld(over);
  const f = wrapFetch ? wrapFetch(w.fetch, w) : w.fetch;
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: f });
  const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
  const states: AppState[] = [];
  controller.subscribe((s) => states.push(s));
  return { w, api, controller, states };
}

const screens = (states: AppState[]) => states.map((s) => (s.screen === "signed-in" ? `signed-in${s.busy ? `:${s.busy}` : ""}` : s.screen));
const noticeOf = (s: AppState) => (s.screen === "signed-out" ? s.notice : null);

describe("sign-in", () => {
  it("starts signed out with no notice, and a session is not even possible yet", () => {
    const { controller, api } = setup();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: null });
    expect(api.hasSession()).toBe(false);
  });

  it("a passkey tap takes it signing-in, then signed-in with the session info", async () => {
    const { controller, states, api } = setup();
    await controller.signIn();
    expect(screens(states)).toEqual(["signing-in", "signed-in"]);
    const s = controller.getState();
    expect(s.screen).toBe("signed-in");
    if (s.screen === "signed-in") {
      expect(s.session.memberships[0]!.role).toBe("staff");
      expect(s.grant.aal).toBe(1);
      expect(s.busy).toBeNull();
    }
    expect(api.hasSession()).toBe(true);
  });

  it("the state never contains the token, anywhere", async () => {
    const { controller, w } = setup();
    await controller.signIn();
    expect(JSON.stringify(controller.getState())).not.toContain(w.server.issuedTokens[0]!);
    expect(JSON.stringify(controller.getState())).not.toContain("gr_ps_");
  });

  it("a cancelled prompt returns to signed-out with a 'cancelled' error and no session", async () => {
    const { controller, w, api } = setup();
    w.auth.failNextWith = "NotAllowedError";
    await controller.signIn();
    expect(noticeOf(controller.getState())).toEqual({ kind: "error", message: { key: "error.cancelled" } });
    expect(api.hasSession()).toBe(false);
    expect(w.server.sessions()).toEqual([]);
  });

  it("cancelSignIn aborts a prompt that is waiting", async () => {
    const w = makeWorld();
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const waiting: Pick<CredentialsContainer, "get"> = {
      get: (req) =>
        new Promise((_resolve, reject) => {
          req?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
        }),
    };
    const controller = createController({ api, webauthn: { credentials: waiting, supported: true } });
    const p = controller.signIn();
    await new Promise((r) => setTimeout(r, 20));
    expect(controller.getState().screen).toBe("signing-in");
    controller.cancelSignIn();
    await p;
    expect(noticeOf(controller.getState())).toEqual({ kind: "error", message: { key: "error.cancelled" } });
  });

  it("a refused assertion shows the sign-in-failed message, not a server string", async () => {
    const { controller, w } = setup();
    w.auth.knobs.flags = 0x01;
    await controller.signIn();
    expect(noticeOf(controller.getState())).toEqual({ kind: "error", message: { key: "error.signInFailed" } });
  });

  it("if the session cannot be read right after verify, the token is dropped and the screen is signed-out", async () => {
    const { controller, api } = setup({}, (f, w) => (async (input, init) => {
      const res = await f(input, init);
      if (String(input).endsWith("/verify")) w.server.killAllSessions();
      return res;
    }) as typeof fetch);
    await controller.signIn();
    expect(api.hasSession()).toBe(false);
    expect(controller.getState().screen).toBe("signed-out");
    expect(noticeOf(controller.getState())?.kind).toBe("error");
  });

  it("an unreachable server is a 'network' error and leaves nothing behind", async () => {
    const { controller, api } = setup({}, () => (async () => Promise.reject(new TypeError("offline"))) as typeof fetch);
    await controller.signIn();
    expect(noticeOf(controller.getState())).toEqual({ kind: "error", message: { key: "error.network" } });
    expect(api.hasSession()).toBe(false);
  });

  it("signIn while signing in or signed in does nothing", async () => {
    const { controller, w } = setup();
    await controller.signIn();
    const calls = w.server.log.length;
    await controller.signIn();
    expect(w.server.log.length).toBe(calls);
  });
});

describe("refresh", () => {
  it("re-reads the session (busy while it runs) and keeps the screen", async () => {
    const { controller, states } = setup();
    await controller.signIn();
    states.length = 0;
    await controller.refresh();
    expect(screens(states)).toEqual(["signed-in:refresh", "signed-in"]);
  });

  it("a session the server killed is a 401: the app is signed-out with 'expired' and the token is gone", async () => {
    const { controller, w, api } = setup();
    await controller.signIn();
    w.server.killAllSessions();
    await controller.refresh();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "expired" } });
    expect(api.hasSession()).toBe(false);
  });

  it("a network failure on refresh keeps the session and shows the error", async () => {
    let offline = false;
    const { controller, api } = setup({}, (f) => (async (input, init) => (offline ? Promise.reject(new TypeError("offline")) : f(input, init))) as typeof fetch);
    await controller.signIn();
    offline = true;
    await controller.refresh();
    const s = controller.getState();
    expect(s.screen).toBe("signed-in");
    if (s.screen === "signed-in") expect(s.notice).toEqual({ kind: "error", message: { key: "error.network" } });
    expect(api.hasSession()).toBe(true);
  });
});

describe("lock and sign-out clear state", () => {
  it("sign-out: signed-out with the 'signed out' notice, the token wiped, the session revoked on the server", async () => {
    const { controller, w, api } = setup();
    await controller.signIn();
    await controller.signOut();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "signed-out" } });
    expect(api.hasSession()).toBe(false);
    expect(w.server.state.signOutCalls).toBe(1);
    expect(JSON.stringify(controller.getState())).not.toContain("memberships");
  });

  it("lock: signed-out with the 'locked' notice, the token wiped, the server told (the session itself is left to expire)", async () => {
    const { controller, w, api } = setup();
    await controller.signIn();
    await controller.lock();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked" } });
    expect(api.hasSession()).toBe(false);
    expect(w.server.state.lockCalls).toBe(1);
    expect(w.server.state.revokedSessions.size).toBe(0);
  });

  it("after a lock the next sign-in needs a NEW passkey tap and opens a NEW session", async () => {
    const { controller, w } = setup();
    await controller.signIn();
    await controller.lock();
    expect(w.auth.requests).toHaveLength(1);
    await controller.signIn();
    expect(w.auth.requests).toHaveLength(2);
    expect(w.server.sessions()).toHaveLength(2);
    expect(w.server.issuedTokens[0]).not.toBe(w.server.issuedTokens[1]);
  });

  it("an unreachable server does not keep the token: sign-out and lock both end signed-out, with an honest notice", async () => {
    for (const [op, kind] of [["signOut", "sign-out-offline"], ["lock", "lock-offline"]] as const) {
      let offline = false;
      const { controller, api } = setup({}, (f) => (async (input, init) => (offline ? Promise.reject(new TypeError("offline")) : f(input, init))) as typeof fetch);
      await controller.signIn();
      offline = true;
      await controller[op]();
      expect(controller.getState(), op).toEqual({ screen: "signed-out", notice: { kind } });
      expect(api.hasSession(), op).toBe(false);
    }
  });

  it("a second click while one is running does not send a second request", async () => {
    const { controller, w } = setup();
    await controller.signIn();
    const p = controller.signOut();
    void controller.signOut();
    await p;
    expect(w.server.state.signOutCalls).toBe(1);
  });

  it("buttons do nothing when signed out", async () => {
    const { controller, w } = setup();
    await controller.signOut();
    await controller.lock();
    await controller.refresh();
    expect(w.server.log).toEqual([]);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: null });
  });

  it("any wipe of the token (a 401 elsewhere, forgetSession) moves the app to signed-out", async () => {
    const { controller, api } = setup();
    await controller.signIn();
    api.forgetSession();
    expect(controller.getState().screen).toBe("signed-out");
  });
});

describe("a reload", () => {
  it("is a fresh controller and a fresh client: signed-out with no token, while the old server session is still live, and it needs a new passkey tap", async () => {
    const first = setup();
    await first.controller.signIn();
    const world = first.w;
    expect(world.server.sessions()).toHaveLength(1);
    // the page is reloaded: new module state, new closure
    const api2 = createPartnerApi({ baseUrl: API_BASE, fetch: world.fetch });
    const second = createController({ api: api2, webauthn: { credentials: world.auth.credentials, supported: true } });
    expect(second.getState()).toEqual({ screen: "signed-out", notice: null });
    expect(api2.hasSession()).toBe(false);
    const before = world.server.log.length;
    await second.refresh();
    expect(world.server.log.length).toBe(before);
    expect(world.auth.requests).toHaveLength(1);
    await second.signIn();
    expect(world.auth.requests).toHaveLength(2);
  });
});

describe("storage", () => {
  let spies: StorageSpies;
  beforeEach(() => {
    spies = installStorageSpies();
  });
  afterEach(() => spies.restore());

  it("sign-in, refresh, lock, sign-in, sign-out and every failure path touch no storage API, no cookie and no console", async () => {
    const { controller, w } = setup();
    w.auth.failNextWith = "NotAllowedError";
    await controller.signIn();
    await controller.signIn();
    await controller.refresh();
    await controller.lock();
    await controller.signIn();
    await controller.signOut();
    expect(spies.calls).toEqual([]);
  });
});
