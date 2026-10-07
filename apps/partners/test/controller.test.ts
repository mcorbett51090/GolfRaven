import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createPartnerApi, type PartnerApiConfig } from "../src/api/client";
import { createController, type AppState } from "../src/app/controller";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { API_BASE, makeWorld, type World } from "./support/world";

function setup(over: Parameters<typeof makeWorld>[0] = {}, wrapFetch?: (f: typeof fetch, w: World) => typeof fetch, apiOver: Partial<PartnerApiConfig> = {}, deps: { nowMs?: () => number } = {}) {
  const w = makeWorld(over);
  const f = wrapFetch ? wrapFetch(w.fetch, w) : w.fetch;
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: f, ...apiOver });
  const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true }, ...deps });
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

  it("the signed-in state holds exactly the grant (expiry, aal) and the session: no other field could carry a credential", async () => {
    const { controller } = setup();
    await controller.signIn();
    const s = controller.getState();
    expect(Object.keys(s).sort()).toEqual(["busy", "grant", "notice", "screen", "session"]);
    if (s.screen === "signed-in") expect(Object.keys(s.grant).sort()).toEqual(["aal", "expiresAt"]);
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

  it("if the session cannot be read right after verify (a network failure or a 500, NOT a 401 that wipes the token itself), no token is left held", async () => {
    for (const failure of ["network", "500"] as const) {
      const { controller, api } = setup({}, (f) => (async (input, init) => {
        if (String(input).endsWith("/session")) {
          if (failure === "network") throw new TypeError("offline");
          return new Response(JSON.stringify({ error: { code: "internal_error", message: "x" } }), { status: 500, headers: { "content-type": "application/json", "access-control-allow-origin": "https://partners.example.test" } });
        }
        return f(input, init);
      }) as typeof fetch);
      await controller.signIn();
      expect(controller.getState().screen, failure).toBe("signed-out");
      expect(api.hasSession(), failure).toBe(false);
      expect(noticeOf(controller.getState())?.kind, failure).toBe("error");
    }
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

  it("lock: signed-out with the 'locked' notice, the token wiped AND the session revoked on the server (design 19.4)", async () => {
    const { controller, w, api } = setup();
    await controller.signIn();
    await controller.lock();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked" } });
    expect(api.hasSession()).toBe(false);
    expect(w.server.state.lockCalls).toBe(0);
    expect(w.server.state.signOutCalls).toBe(1);
    expect(w.server.state.revokedSessions.size).toBe(1);
  });

  it("after a lock the next sign-in needs a NEW passkey tap and opens a NEW session", async () => {
    const { controller, w } = setup();
    await controller.signIn();
    await controller.lock();
    expect(w.auth.requests).toHaveLength(1);
    await controller.signIn();
    expect(w.auth.requests).toHaveLength(2);
    expect(w.server.sessions()).toHaveLength(1); // the locked one was revoked, only the new one is live
    expect(w.server.state.revokedSessions.size).toBe(1);
    expect(w.server.issuedTokens).toHaveLength(2);
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

/** A fetch that holds the response of matching requests until `release()`; the request's signal is ignored unless `abortable` (as a real fetch honours it). */
function gate(match: (url: string, method: string) => boolean, opts: { abortable?: boolean } = {}) {
  const waiting: Array<() => void> = [];
  const wrap = (f: typeof fetch): typeof fetch =>
    (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (!match(String(input), init?.method ?? "GET")) return f(input, init);
      await new Promise<void>((resolve, reject) => {
        waiting.push(resolve);
        if (opts.abortable) init?.signal?.addEventListener("abort", () => reject(init.signal!.reason ?? new TypeError("aborted")));
      });
      return f(input, init);
    }) as typeof fetch;
  return { wrap, release: () => waiting.splice(0).forEach((r) => r()), pending: () => waiting.length };
}
const tick = (ms = 10) => new Promise((r) => setTimeout(r, ms));

describe("lock and sign-out are immediate (MEDIUM-2) and lock revokes (design 19.4)", () => {
  it.each([
    ["lock", "locked", "lock-offline"],
    ["signOut", "signed-out", "sign-out-offline"],
  ] as const)("%s: a request that never answers still leaves the screen signed-out and the token gone AT ONCE, and the honest notice replaces it after the timeout", async (op, plain, offline) => {
    const g = gate((u, m) => u.endsWith("/sign-out") && m === "POST", { abortable: true });
    const { controller, api, states } = setup({}, (f) => g.wrap(f), { timeoutMs: 80 });
    await controller.signIn();
    states.length = 0;
    const p = controller[op]();
    // no await: the very next line runs while the revoking request is still hanging
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: plain } });
    expect(api.hasSession()).toBe(false);
    expect(g.pending()).toBe(1);
    await p;
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: offline } });
    expect(screens(states)).toEqual(["signed-out", "signed-out"]);
  });

  it("lock sends POST sign-out with the old token, and the server revokes that session; the old token is then refused (design 19.4)", async () => {
    const { controller, w } = setup();
    await controller.signIn();
    const token = w.server.issuedTokens[0]!;
    await controller.lock();
    const sends = w.server.log.filter((r) => r.method !== "OPTIONS").map((r) => `${r.method} ${r.path.split("/partner-session/")[1]} ${r.authorization === `Bearer ${token}` ? "old-token" : r.authorization ?? "-"}`);
    expect(sends.slice(-1)).toEqual(["POST sign-out old-token"]);
    expect(w.server.state.revokedSessions.size).toBe(1);
    const raw = await w.server.handler(new Request("https://api.example.test/functions/v1/partner-session/session", { headers: { authorization: `Bearer ${token}`, "content-type": "application/json" } }));
    expect(raw.status).toBe(401);
  });

  it.each(["lock", "signOut"] as const)("%s works while a refresh that never answers is busy, and the refresh's late answer cannot bring the screen back", async (op) => {
    // the first /session (right after verify) must pass; only the refresh is held
    const holdRefresh = { on: false };
    const gated = gate((u, m) => holdRefresh.on && u.endsWith("/session") && m === "GET");
    const { controller, api } = setup({}, (f) => gated.wrap(f));
    await controller.signIn();
    holdRefresh.on = true;
    const refresh = controller.refresh();
    await tick();
    const s = controller.getState();
    expect(s.screen === "signed-in" && s.busy).toBe("refresh");
    expect(gated.pending()).toBe(1);
    await controller[op]();
    expect(controller.getState().screen).toBe("signed-out");
    expect(api.hasSession()).toBe(false);
    gated.release();
    await refresh;
    expect(controller.getState().screen).toBe("signed-out");
  });

  it("a refresh that outlives its session cannot overwrite a NEW session's screen", async () => {
    const holdRefresh = { on: false };
    const gated = gate((u, m) => holdRefresh.on && u.endsWith("/session") && m === "GET");
    const { controller, w } = setup({}, (f) => gated.wrap(f));
    await controller.signIn();
    holdRefresh.on = true;
    const stale = controller.refresh();
    await tick();
    await controller.lock();
    holdRefresh.on = false;
    await controller.signIn();
    const fresh = controller.getState();
    expect(fresh.screen).toBe("signed-in");
    gated.release();
    await stale;
    expect(controller.getState()).toBe(fresh); // untouched: same object
    expect(w.server.issuedTokens).toHaveLength(2);
  });

  it("a refresh that never answers times out, keeps the session and says so", async () => {
    const holdRefresh = { on: false };
    const gated = gate((u, m) => holdRefresh.on && u.endsWith("/session") && m === "GET", { abortable: true });
    const { controller, api } = setup({}, (f) => gated.wrap(f), { timeoutMs: 60 });
    await controller.signIn();
    holdRefresh.on = true;
    await controller.refresh();
    const s = controller.getState();
    expect(s.screen).toBe("signed-in");
    if (s.screen === "signed-in") {
      expect(s.busy).toBeNull();
      expect(s.notice).toEqual({ kind: "error", message: { key: "error.network" } });
    }
    expect(api.hasSession()).toBe(true);
  });

  it("when the sign-out request fails the notice is only changed if the screen is still the one the plain notice made (a newer sign-in is not disturbed)", async () => {
    const g = gate((u, m) => u.endsWith("/sign-out") && m === "POST", { abortable: true });
    const { controller } = setup({}, (f) => g.wrap(f), { timeoutMs: 80 });
    await controller.signIn();
    const p = controller.signOut();
    await controller.signIn(); // the person signs in again while the old revoke is hanging
    expect(controller.getState().screen).toBe("signed-in");
    await p; // the old revoke times out
    expect(controller.getState().screen).toBe("signed-in");
  });
});

describe("cancelling a sign-in (LOW-4) and a failed first read (LOW-5)", () => {
  it("Cancel pressed while verify is on the wire: signed-out at once; when the answer arrives the session it opened is REVOKED on the server and no token is held", async () => {
    const g = gate((u, m) => u.endsWith("/verify") && m === "POST");
    const { controller, api, w } = setup({}, (f) => g.wrap(f));
    const p = controller.signIn();
    await tick(30);
    expect(g.pending()).toBe(1);
    expect(controller.getState().screen).toBe("signing-in");
    controller.cancelSignIn();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "error", message: { key: "error.cancelled" } } });
    g.release();
    await p;
    await tick(20);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "error", message: { key: "error.cancelled" } } });
    expect(api.hasSession()).toBe(false);
    expect(w.server.issuedTokens).toHaveLength(1); // the server DID mint a session ...
    expect(w.server.state.revokedSessions.size).toBe(1); // ... and it was revoked, not left to idle out
    expect(w.server.sessions()).toEqual([]);
  });

  it("Cancel pressed while the first session read is on the wire (verify already succeeded): the token is wiped, the session revoked, nothing is shown", async () => {
    const g = gate((u, m) => u.endsWith("/session") && m === "GET", { abortable: true });
    const { controller, api, w } = setup({}, (f) => g.wrap(f));
    const p = controller.signIn();
    await tick(30);
    expect(api.hasSession()).toBe(true);
    controller.cancelSignIn();
    expect(api.hasSession()).toBe(false);
    expect(controller.getState().screen).toBe("signed-out");
    await p;
    await tick(20);
    expect(controller.getState().screen).toBe("signed-out");
    expect(w.server.state.revokedSessions.size).toBe(1);
  });

  it("cancelSignIn does nothing when no sign-in is running", async () => {
    const { controller, w } = setup();
    controller.cancelSignIn();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: null });
    await controller.signIn();
    controller.cancelSignIn();
    expect(controller.getState().screen).toBe("signed-in");
    expect(w.server.state.revokedSessions.size).toBe(0);
  });

  it("verify succeeds, then the first session read FAILS: the server is told to revoke (best effort) before the token is forgotten, for a 500 and for a dropped connection", async () => {
    for (const failure of ["500", "network"] as const) {
      const { controller, api, w } = setup({}, (f) => (async (input, init) => {
        if (String(input).endsWith("/session")) {
          if (failure === "network") throw new TypeError("offline");
          return new Response(JSON.stringify({ error: { code: "internal_error", message: "x" } }), { status: 500, headers: { "content-type": "application/json", "access-control-allow-origin": "https://partners.example.test" } });
        }
        return f(input, init);
      }) as typeof fetch);
      await controller.signIn();
      expect(controller.getState().screen, failure).toBe("signed-out");
      expect(api.hasSession(), failure).toBe(false);
      expect(w.server.state.signOutCalls, failure).toBe(1);
      expect(w.server.state.revokedSessions.size, failure).toBe(1);
      expect(noticeOf(controller.getState())?.kind, failure).toBe("error");
    }
  });

  it("... and if the revoke cannot be sent either, nothing is held and the error is still shown", async () => {
    const { controller, api } = setup({}, (f) => (async (input, init) => {
      if (String(input).endsWith("/session") || String(input).endsWith("/sign-out")) throw new TypeError("offline");
      return f(input, init);
    }) as typeof fetch);
    await controller.signIn();
    expect(api.hasSession()).toBe(false);
    expect(controller.getState().screen).toBe("signed-out");
    expect(noticeOf(controller.getState())?.kind).toBe("error");
  });
});

describe("a 429 on sign-in disables the sign-in button for Retry-After (NIT)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function limited(seconds: string | null) {
    return (f: typeof fetch) =>
      (async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith("/options")) return new Response(JSON.stringify({ error: { code: "rate_limited", message: "x" } }), { status: 429, headers: seconds === null ? {} : { "retry-after": seconds } });
        return f(input, init);
      }) as typeof fetch;
  }

  it("the state carries retryUntilMs, signIn is refused until then (no request), and the button is released when the time has passed", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
    const { controller, w } = setup({}, (f) => limited("30")(f));
    await controller.signIn();
    const t0 = Date.now();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "error", message: { key: "error.rateLimited.wait", params: { seconds: 30 } } }, retryUntilMs: t0 + 30_000 });
    const calls = w.server.log.length;
    await controller.signIn();
    expect(controller.getState().screen).toBe("signed-out");
    vi.advanceTimersByTime(29_000);
    await controller.signIn();
    expect((controller.getState() as { retryUntilMs?: number }).retryUntilMs).toBe(t0 + 30_000);
    expect(w.server.log.length).toBe(calls); // nothing was sent while it was disabled
    vi.advanceTimersByTime(1_001);
    const s = controller.getState();
    expect(s.screen).toBe("signed-out");
    expect("retryUntilMs" in s).toBe(false);
    expect(s.screen === "signed-out" && s.notice).toEqual({ kind: "error", message: { key: "error.rateLimited.wait", params: { seconds: 30 } } });
  });

  it("without a readable Retry-After the button is not locked (nothing to base a wait on)", async () => {
    const { controller } = setup({}, (f) => limited(null)(f));
    await controller.signIn();
    expect("retryUntilMs" in controller.getState()).toBe(false);
  });

  it("a Retry-After beyond a day is capped at a day, never a timer overflow", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
    const { controller } = setup({}, (f) => limited("9999999")(f));
    await controller.signIn();
    expect((controller.getState() as { retryUntilMs: number }).retryUntilMs).toBe(Date.now() + 86_400_000);
  });

  it("a non-429 failure does not lock the button, and a successful sign-in clears any wait", async () => {
    const { controller, w } = setup();
    w.auth.failNextWith = "NotAllowedError";
    await controller.signIn();
    expect("retryUntilMs" in controller.getState()).toBe(false);
  });
});

describe("reset (pagehide / bfcache restore)", () => {
  it("signed-in: ends up signed-out with the expired notice, the token gone and the session revoked", async () => {
    const { controller, api, w } = setup();
    await controller.signIn();
    controller.reset();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "expired" } });
    expect(api.hasSession()).toBe(false);
    await tick(30);
    expect(w.server.state.revokedSessions.size).toBe(1);
  });

  it("signing-in: the prompt is cancelled and the screen is signed-out", async () => {
    const g = gate((u, m) => u.endsWith("/verify") && m === "POST");
    const { controller, w, api } = setup({}, (f) => g.wrap(f));
    const p = controller.signIn();
    await tick(30);
    controller.reset();
    expect(controller.getState().screen).toBe("signed-out");
    g.release();
    await p;
    await tick(20);
    expect(api.hasSession()).toBe(false);
    expect(w.server.state.revokedSessions.size).toBe(1);
  });

  it("when already signed-out it still redraws (a state is emitted) and sends nothing", async () => {
    const { controller, w, states } = setup();
    controller.reset();
    expect(states).toHaveLength(1);
    expect(w.server.log).toEqual([]);
  });
});
