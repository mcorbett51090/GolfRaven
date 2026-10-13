/**
 * Page lifecycle (MEDIUM-1): `pagehide` ends the session, `pageshow` with `persisted` forces signed-out. The Playwright suite proves the same against
 * Chromium's real back/forward cache; these cells pin the handler logic without a browser.
 *
 * The auto-lock (owner decision: lock after 120 000 ms hidden; design 140) is pinned at the bottom with a fake document, an injected clock and injected timers.
 */
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController, type AppController, type AppState } from "../src/app/controller";
import { AUTO_LOCK_HIDDEN_MS, installAutoLock, installPageLifecycle } from "../src/app/lifecycle";
import { noticeText } from "../src/ui/notice";
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

  it("main.ts wires the auto-lock to the page's own document, with the controller (and no injected clock or timer: the real ones)", () => {
    const main = readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
    expect(main).toMatch(/installAutoLock\(controller,\s*\{\s*document\s*\}\)/);
  });
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// The auto-lock: a page hidden for AUTO_LOCK_HIDDEN_MS (120 000 ms, the owner's decision) locks itself.
// ---------------------------------------------------------------------------------------------------------------------------------------------

/** A `document` with a settable `visibilityState`; `hide()` / `show()` change it and fire `visibilitychange` the way a browser does. */
class FakeDocument extends EventTarget {
  visibilityState: "visible" | "hidden" = "visible";
  hide(): void {
    this.visibilityState = "hidden";
    this.dispatchEvent(new Event("visibilitychange"));
  }
  show(): void {
    this.visibilityState = "visible";
    this.dispatchEvent(new Event("visibilitychange"));
  }
}

/**
 * A wall clock, a monotonic clock and timers. The timers run on the monotonic clock, as a browser's do, so moving the wall clock never moves a timer.
 *   - `advance`: time passing normally. Both clocks move and every due timer fires, in order, at its own instant.
 *   - `elapse`: time passing for a FROZEN page on a device that is awake. Both clocks move and NO timer runs (iOS freezes a backgrounded page).
 *   - `jump`: the WALL clock moving alone with no timer: a clock that is set, or a device asleep whose monotonic clock stood still. The return-path cells
 *     use it, so the timer cannot be what locks.
 *   - `monoJump`: the monotonic clock moving alone (only to model a broken one).
 */
function fakeClock(start = 1_800_000_000_000) {
  let wall = start;
  let mono = 0;
  let next = 1;
  const timers = new Map<number, { at: number; fn: () => void; ms: number }>();
  let override: (() => number) | null = null;
  let monoOverride: (() => number) | null = null;
  return {
    now: () => (override === null ? wall : override()),
    monoNow: () => (monoOverride === null ? mono : monoOverride()),
    setTimer: (fn: () => void, ms: number): unknown => {
      const id = next++;
      timers.set(id, { at: mono + ms, fn, ms });
      return id;
    },
    clearTimer: (h: unknown): void => {
      timers.delete(h as number);
    },
    advance(ms: number): void {
      const end = mono + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, v]) => v.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (due === undefined) break;
        timers.delete(due[0]);
        wall += Math.max(0, due[1].at - mono);
        mono = Math.max(mono, due[1].at);
        due[1].fn();
      }
      wall += end - mono;
      mono = end;
    },
    jump(ms: number): void {
      wall += ms;
    },
    elapse(ms: number): void {
      wall += ms;
      mono += ms;
    },
    monoJump(ms: number): void {
      mono += ms;
    },
    /** From now on `now()` returns what `f` says (a clock that is broken). */
    breakWith(f: () => number): void {
      override = f;
    },
    /** From now on `monoNow()` returns what `f` says. */
    breakMonoWith(f: () => number): void {
      monoOverride = f;
    },
    pendingDelays: (): number[] => [...timers.values()].map((v) => v.ms),
  };
}

/** A passkey prompt that stays open until `release()`, and rejects with an AbortError when the page cancels it (as the browser does). */
function openPasskeySheet(inner: Pick<CredentialsContainer, "get" | "create">, which: "get" | "create" = "get") {
  let release!: () => void;
  const released = new Promise<void>((r) => {
    release = r;
  });
  let entered!: () => void;
  const isOpen = new Promise<void>((r) => {
    entered = r;
  });
  const sheet =
    (answer: (req?: never) => Promise<Credential | null>) =>
    (req?: { signal?: AbortSignal }) =>
      new Promise<Credential | null>((resolve, reject) => {
        const fail = () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        const signal = req?.signal;
        entered();
        if (signal?.aborted) return fail();
        signal?.addEventListener("abort", fail, { once: true });
        void released.then(() => answer(req as never).then(resolve, reject));
      });
  const credentials: Pick<CredentialsContainer, "get" | "create"> = {
    create: which === "create" ? (sheet((req) => inner.create(req)) as CredentialsContainer["create"]) : inner.create.bind(inner),
    get: which === "get" ? (sheet((req) => inner.get(req)) as CredentialsContainer["get"]) : inner.get.bind(inner),
  };
  return { credentials, release, isOpen };
}

/** Holds the response of matching requests until `release()`. `abortable`: the request's signal ends the wait, as a real fetch honours it. */
function holdResponses(match: (url: string, method: string) => boolean, opts: { abortable?: boolean } = {}) {
  const waiting: Array<() => void> = [];
  const signals: Array<AbortSignal | undefined> = [];
  const wrap =
    (f: typeof fetch): typeof fetch =>
    (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (!match(String(input), init?.method ?? "GET")) return f(input, init);
      signals.push(init?.signal ?? undefined);
      await new Promise<void>((resolve, reject) => {
        waiting.push(resolve);
        if (opts.abortable) init?.signal?.addEventListener("abort", () => reject(init.signal!.reason ?? new TypeError("aborted")));
      });
      return f(input, init);
    }) as typeof fetch;
  return { wrap, release: () => waiting.splice(0).forEach((r) => r()), pending: () => waiting.length, signals };
}

interface SentRequest {
  readonly url: string;
  readonly method: string;
  readonly keepalive: boolean | undefined;
  readonly authorization: string | null;
  /** What the page looked like at the moment the request was handed to fetch. */
  readonly hasSessionAtSend: boolean;
  readonly screenAtSend: AppState["screen"];
}

/** The real client, controller, page-lifecycle handlers and auto-lock, over the fake server, with a fake document, a fake clock and fake timers. */
function autoSetup(opts: { wrapFetch?: (f: typeof fetch) => typeof fetch; sheet?: boolean; createSheet?: boolean } = {}) {
  const w = makeWorld();
  const sheet = opts.sheet === true ? openPasskeySheet(w.auth.credentials) : null;
  const createSheet = opts.createSheet === true ? openPasskeySheet(w.auth.credentials, "create") : null;
  const sent: SentRequest[] = [];
  const holder: { api?: ReturnType<typeof createPartnerApi>; controller?: AppController } = {};
  const recording = (async (input: RequestInfo | URL, init?: RequestInit) => {
    sent.push({
      url: String(input),
      method: init?.method ?? "GET",
      keepalive: init?.keepalive,
      authorization: new Headers(init?.headers).get("authorization"),
      hasSessionAtSend: holder.api!.hasSession(),
      screenAtSend: holder.controller!.getState().screen,
    });
    return w.fetch(input, init);
  }) as typeof fetch;
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: opts.wrapFetch ? opts.wrapFetch(recording) : recording });
  const controller = createController({ api, webauthn: { credentials: sheet?.credentials ?? createSheet?.credentials ?? w.auth.credentials, supported: true } });
  holder.api = api;
  holder.controller = controller;
  const states: AppState[] = [];
  controller.subscribe((st) => states.push(st));
  const doc = new FakeDocument();
  const clock = fakeClock();
  const target = new EventTarget();
  installPageLifecycle(target, api, controller);
  installAutoLock(controller, { document: doc, nowMs: clock.now, monoMs: clock.monoNow, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  const pagehide = () => target.dispatchEvent(new Event("pagehide"));
  const pageshow = (persisted: boolean) => target.dispatchEvent(Object.assign(new Event("pageshow"), { persisted }));
  /** The requests that revoke a session: POST lock / POST sign-out, which carry a bearer. */
  const revokes = () => sent.filter((r) => r.authorization !== null && /\/(lock|sign-out)$/.test(r.url));
  return { w, api, controller, states, doc, clock, sent, sheet, createSheet, revokes, pagehide, pageshow };
}

const noticeKind = (st: AppState): string | null => (st.screen === "signed-out" ? (st.notice?.kind ?? null) : null);
const CANCELLED = { screen: "signed-out", notice: { kind: "error", message: { key: "error.cancelled" } } } as const;
/** The screen after the auto-lock cancels an enrolment. */
const STOPPED_SCREEN = { screen: "signed-out", notice: { kind: "enrol-stopped" } } as const;

/** A stand-in controller that only records what the auto-lock asks of it. */
function stubController(state: { screen: AppState["screen"]; step?: string }) {
  const calls: string[] = [];
  const controller = {
    getState: () => state as AppState,
    lock: (o?: unknown) => {
      calls.push(`lock ${JSON.stringify(o)}`);
      return Promise.resolve();
    },
    cancelSignIn: (o?: unknown) => void calls.push(`cancelSignIn ${JSON.stringify(o)}`),
    cancelEnrol: (o?: unknown) => void calls.push(`cancelEnrol ${JSON.stringify(o)}`),
    reset: () => void calls.push("reset"),
    signOut: () => void calls.push("signOut"),
  } as unknown as AppController;
  const doc = new FakeDocument();
  const clock = fakeClock();
  installAutoLock(controller, { document: doc, nowMs: clock.now, monoMs: clock.monoNow, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  return { calls, doc, clock };
}

describe("auto-lock: the limit", () => {
  it("is 120 000 ms: two minutes, one exported constant", () => {
    expect(AUTO_LOCK_HIDDEN_MS).toBe(120_000);
  });

  it.each([
    [119_999, false],
    [120_000, true],
    [120_001, true],
    [600_000, true],
  ])("hidden for %i ms (the wall clock moved, no timer ran), then visible: locked = %s", async (ms, locked) => {
    const { controller, doc, clock, api, revokes } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.jump(ms);
    doc.show();
    expect(controller.getState().screen).toBe(locked ? "signed-out" : "signed-in");
    expect(api.hasSession()).toBe(!locked);
    await tick();
    expect(revokes()).toHaveLength(locked ? 1 : 0);
  });

  it("the boundary follows the exported constant (the cells above are literal, so changing the value fails them)", async () => {
    for (const [ms, locked] of [[AUTO_LOCK_HIDDEN_MS - 1, false], [AUTO_LOCK_HIDDEN_MS, true]] as const) {
      const { controller, doc, clock } = autoSetup();
      await controller.signIn();
      doc.hide();
      clock.jump(ms);
      doc.show();
      expect(controller.getState().screen, `${ms}`).toBe(locked ? "signed-out" : "signed-in");
    }
  });
});

describe("auto-lock: what a lock is (exactly what Lock is today)", () => {
  it("on return: signed-out AT ONCE with the 'locked-away' notice; the session is revoked with POST lock carrying the OLD token (not sign-out, not keepalive)", async () => {
    const { controller, doc, clock, api, w, revokes, states } = autoSetup();
    await controller.signIn();
    const token = w.server.issuedTokens[0]!;
    doc.hide();
    clock.jump(AUTO_LOCK_HIDDEN_MS);
    states.length = 0;
    doc.show();
    // no await: the very next line runs while the revoking request is still on its way
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    expect(api.hasSession()).toBe(false);
    expect(states.map((x) => `${x.screen}:${noticeKind(x)}`)).toEqual(["signed-out:locked-away"]); // one transition, never a plain 'locked' first
    await tick();
    expect(revokes()).toHaveLength(1);
    expect(revokes()[0]).toMatchObject({ url: `${API_BASE}/partner-session/lock`, method: "POST", keepalive: undefined, authorization: `Bearer ${token}` });
    expect(w.server.state.lockCalls).toBe(1);
    expect(w.server.state.signOutCalls).toBe(0);
    expect(w.server.state.revokedSessions.size).toBe(1);
    expect(w.server.sessions()).toEqual([]);
  });

  it("the token is wiped and the screen is signed-out BEFORE the revoke is handed to fetch, on both paths", async () => {
    for (const path of ["return", "timer"] as const) {
      const { controller, doc, clock, revokes } = autoSetup();
      await controller.signIn();
      doc.hide();
      if (path === "return") {
        clock.jump(AUTO_LOCK_HIDDEN_MS);
        doc.show();
      } else clock.advance(AUTO_LOCK_HIDDEN_MS);
      await tick();
      expect(revokes(), path).toHaveLength(1);
      expect(revokes()[0]!.hasSessionAtSend, path).toBe(false);
      expect(revokes()[0]!.screenAtSend, path).toBe("signed-out");
    }
  });

  it("the timer path sends the revoke as a KEEPALIVE request (the page is hidden and may be frozen next); the return path does not", async () => {
    const t = autoSetup();
    await t.controller.signIn();
    t.doc.hide();
    t.clock.advance(AUTO_LOCK_HIDDEN_MS);
    await tick();
    expect(t.revokes()[0]!.keepalive).toBe(true);
    const r = autoSetup();
    await r.controller.signIn();
    r.doc.hide();
    r.clock.jump(AUTO_LOCK_HIDDEN_MS);
    r.doc.show();
    await tick();
    expect(r.revokes()[0]!.keepalive).toBeUndefined();
  });

  it("an unreachable server: signed-out at once all the same, then the honest 'could not be reached' notice replaces the plain one", async () => {
    let offline = false;
    const { controller, doc, clock, api } = autoSetup({ wrapFetch: (f) => (async (i, init) => (offline ? Promise.reject(new TypeError("offline")) : f(i, init))) as typeof fetch });
    await controller.signIn();
    offline = true;
    doc.hide();
    clock.jump(AUTO_LOCK_HIDDEN_MS);
    doc.show();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    expect(api.hasSession()).toBe(false);
    await tick();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "lock-offline" } });
  });

  it("it is controller.lock with { away: true, keepalive: <timer path> }: not reset(), not signOut(), not a second implementation", () => {
    const timer = stubController({ screen: "signed-in" });
    timer.doc.hide();
    timer.clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(timer.calls).toEqual(['lock {"away":true,"keepalive":true}']);
    const back = stubController({ screen: "signed-in" });
    back.doc.hide();
    back.clock.jump(AUTO_LOCK_HIDDEN_MS);
    back.doc.show();
    expect(back.calls).toEqual(['lock {"away":true,"keepalive":false}']);
  });

  it("the new notice has its own wording in both languages, different from the Lock button's", () => {
    for (const locale of ["en", "fr-CA"] as const) {
      expect(noticeText({ kind: "locked-away" }, locale), locale).not.toBe(noticeText({ kind: "locked" }, locale));
    }
    expect(noticeText({ kind: "locked-away" }, "en")).toBe("Locked because you were away. Sign in again with your passkey to continue.");
    expect(noticeText({ kind: "locked-away" }, "fr-CA")).toContain("Verrouillé");
  });
});

describe("auto-lock: the timer path (best effort; the only one that acts while the page is still hidden)", () => {
  it("is set for exactly the limit when the page goes hidden, and not before", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    expect(clock.pendingDelays()).toEqual([]);
    doc.hide();
    expect(clock.pendingDelays()).toEqual([120_000]);
  });

  it("fires while hidden: nothing at 119 999 ms, locked at 120 000 ms with the page still hidden", async () => {
    const { controller, doc, clock, api, w, revokes } = autoSetup();
    await controller.signIn();
    const token = w.server.issuedTokens[0]!;
    doc.hide();
    clock.advance(119_999);
    expect(controller.getState().screen).toBe("signed-in");
    expect(revokes()).toHaveLength(0);
    clock.advance(1);
    expect(doc.visibilityState).toBe("hidden");
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    expect(api.hasSession()).toBe(false);
    await tick();
    expect(revokes()).toHaveLength(1);
    expect(revokes()[0]).toMatchObject({ url: `${API_BASE}/partner-session/lock`, authorization: `Bearer ${token}`, keepalive: true });
    expect(w.server.state.revokedSessions.size).toBe(1);
  });

  it("when the page then becomes visible, nothing is sent a second time and the 'locked-away' notice stays", async () => {
    const { controller, doc, clock, revokes } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.advance(AUTO_LOCK_HIDDEN_MS + 5_000);
    await tick();
    doc.show();
    await tick();
    expect(revokes()).toHaveLength(1);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
  });

  it("becoming visible cancels the timer: nothing fires later, however long the clock then runs", async () => {
    const { controller, doc, clock, revokes } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.advance(10_000);
    doc.show();
    expect(clock.pendingDelays()).toEqual([]);
    clock.advance(1_000_000);
    await tick();
    expect(controller.getState().screen).toBe("signed-in");
    expect(revokes()).toHaveLength(0);
  });
});

describe("auto-lock: event sequences", () => {
  it("a timer left over from an EARLIER hide cannot lock a later, shorter one: it was cancelled when the page became visible", async () => {
    const { controller, doc, clock, revokes } = autoSetup();
    await controller.signIn();
    doc.hide(); // the first stretch: its timer would fire at 120 000 ms from here
    clock.advance(10_000);
    doc.show();
    clock.advance(90_000);
    doc.hide(); // the second stretch starts at 100 000 ms
    clock.advance(20_000); // 120 000 ms after the FIRST hide, 20 000 ms into the second
    expect(controller.getState().screen).toBe("signed-in");
    expect(revokes()).toHaveLength(0);
    clock.advance(100_000); // 120 000 ms into the second
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
  });

  it("hidden twice in a row: the first start stands (the repeat neither buys more time nor adds a second timer)", async () => {
    const a = autoSetup();
    await a.controller.signIn();
    a.doc.hide();
    a.clock.advance(100_000);
    a.doc.hide();
    expect(a.clock.pendingDelays()).toEqual([120_000]); // still the one timer from the first hide
    a.clock.advance(20_000);
    expect(a.controller.getState().screen).toBe("signed-out"); // 120 000 after the FIRST hide
    // on the return path: 100 000 + 20 000 since the first hidden, not 20 000 since the second
    const b = autoSetup();
    await b.controller.signIn();
    b.doc.hide();
    b.clock.jump(100_000);
    b.doc.hide();
    b.clock.jump(20_000);
    b.doc.show();
    expect(b.controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
  });

  it("visible with no preceding hidden: nothing happens, however far the clock has moved", async () => {
    const { controller, doc, clock, revokes } = autoSetup();
    await controller.signIn();
    clock.jump(10 * 60 * 60 * 1000);
    doc.show();
    doc.show();
    await tick();
    expect(controller.getState().screen).toBe("signed-in");
    expect(revokes()).toHaveLength(0);
  });

  it("each hidden -> visible cycle is measured on its own: two 60 000 ms hides do not add up, a 130 000 ms one locks", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.jump(60_000);
    doc.show();
    expect(controller.getState().screen).toBe("signed-in");
    doc.hide();
    clock.jump(60_000); // 120 000 of hidden time in all, but never more than 60 000 in a row
    doc.show();
    expect(controller.getState().screen).toBe("signed-in");
    doc.hide();
    clock.jump(130_000);
    doc.show();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
  });

  it("after a lock and a new sign-in the earlier hidden stretch is forgotten: a short hide does not lock the new session", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.advance(AUTO_LOCK_HIDDEN_MS);
    doc.show();
    await tick();
    expect(controller.getState().screen).toBe("signed-out");
    await controller.signIn();
    expect(controller.getState().screen).toBe("signed-in");
    doc.hide();
    clock.jump(30_000);
    doc.show();
    expect(controller.getState().screen).toBe("signed-in");
  });

  it("a clock that went BACKWARDS cannot prove the page was away briefly, so it locks (fail closed); so does a clock that is not a number", async () => {
    const back = autoSetup();
    await back.controller.signIn();
    back.doc.hide();
    back.clock.jump(-5_000);
    back.doc.show();
    expect(back.controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    const nan = autoSetup();
    await nan.controller.signIn();
    nan.doc.hide();
    nan.clock.breakWith(() => Number.NaN);
    nan.doc.show();
    expect(nan.controller.getState().screen).toBe("signed-out");
  });

  it("a clock that moves back while the timer is pending does not stop the timer from locking", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.jump(-1_000_000);
    clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(controller.getState().screen).toBe("signed-out");
  });
});

describe("auto-lock: two clocks (a wall clock that is set back must not buy time)", () => {
  it("G1: the device is awake and the page is frozen for 10 minutes, then someone sets the date back to 10 s after the page went hidden: the wall clock says 10 s, the monotonic clock says 10 minutes, and it LOCKS", async () => {
    const { controller, doc, clock, api, w, revokes } = autoSetup();
    await controller.signIn();
    const token = w.server.issuedTokens[0]!;
    doc.hide();
    clock.elapse(600_000); // 10 minutes pass; the frozen page runs no timer
    clock.jump(-590_000); // the date is set back to hide + 10 s
    doc.show();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    expect(api.hasSession()).toBe(false);
    await tick();
    expect(revokes()).toHaveLength(1);
    expect(revokes()[0]).toMatchObject({ url: `${API_BASE}/partner-session/lock`, authorization: `Bearer ${token}` });
    expect(w.server.state.revokedSessions.size).toBe(1);
  });

  it("the date set back to exactly the moment the page went hidden (a wall-clock elapsed of 0) locks too", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.elapse(300_000);
    clock.jump(-300_000);
    doc.show();
    expect(controller.getState().screen).toBe("signed-out");
  });

  it.each([
    [119_999, false],
    [120_000, true],
    [120_001, true],
  ])("the monotonic clock alone is judged on the same limit: %i ms of monotonic time with the wall clock showing none, locked = %s", async (ms, locked) => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.elapse(ms);
    clock.jump(-ms); // the wall clock is back where it started
    doc.show();
    expect(controller.getState().screen).toBe(locked ? "signed-out" : "signed-in");
  });

  it("both clocks agree on a short absence: it stays (the control for the cells above)", async () => {
    const { controller, doc, clock, revokes } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.elapse(60_000);
    doc.show();
    await tick();
    expect(controller.getState().screen).toBe("signed-in");
    expect(revokes()).toHaveLength(0);
  });

  it("the opposite: the wall clock jumps FORWARD past the limit while the monotonic clock says the page was away briefly. It locks. That is intended: a forward jump can only lock early, which costs one passkey tap, never late", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.jump(130_000);
    doc.show();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
  });

  it("a monotonic clock that is not a number, or that went backwards, locks (fail closed), as the wall clock does", async () => {
    const nan = autoSetup();
    await nan.controller.signIn();
    nan.doc.hide();
    nan.clock.breakMonoWith(() => Number.NaN);
    nan.doc.show();
    expect(nan.controller.getState().screen).toBe("signed-out");
    const back = autoSetup();
    await back.controller.signIn();
    back.doc.hide();
    back.clock.monoJump(-5_000);
    back.doc.show();
    expect(back.controller.getState().screen).toBe("signed-out");
    const broken = autoSetup(); // not a number already when the page went hidden
    await broken.controller.signIn();
    broken.clock.breakMonoWith(() => Number.NaN);
    broken.doc.hide();
    broken.doc.show();
    expect(broken.controller.getState().screen).toBe("signed-out");
  });

  it("a repeated hidden does not restart the monotonic stretch either: 100 000 + 20 000 ms since the FIRST hide locks with the wall clock set back", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.elapse(100_000);
    doc.hide();
    clock.elapse(20_000);
    clock.jump(-120_000);
    doc.show();
    expect(controller.getState().screen).toBe("signed-out");
  });

  it("a fresh stretch reads both clocks again: after a short hide the next hide starts from now on both", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.elapse(60_000);
    doc.show();
    clock.elapse(500_000); // visible for a long time: not an absence
    doc.hide();
    clock.elapse(60_000);
    clock.jump(-60_000);
    doc.show();
    expect(controller.getState().screen).toBe("signed-in");
  });

  it("the timer path does not read either clock: a wall clock set back and a monotonic clock that stands still do not stop it", async () => {
    const { controller, doc, clock } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.jump(-1_000_000);
    clock.breakMonoWith(() => 0);
    clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(controller.getState().screen).toBe("signed-out");
  });
});

describe("auto-lock: states that hold no session", () => {
  it("signed out: nothing is sent and the state object is untouched, however long the page is hidden (both paths)", async () => {
    const { controller, doc, clock, sent } = autoSetup();
    const before = controller.getState();
    doc.hide();
    clock.advance(AUTO_LOCK_HIDDEN_MS * 2);
    doc.show();
    doc.hide();
    clock.jump(AUTO_LOCK_HIDDEN_MS * 2);
    doc.show();
    await tick();
    expect(sent).toEqual([]);
    expect(controller.getState()).toBe(before);
  });

  it("after a sign-out the notice stays 'signed out' (the auto-lock does not rewrite it) and nothing more is sent", async () => {
    const { controller, doc, clock, sent } = autoSetup();
    await controller.signIn();
    await controller.signOut();
    const n = sent.length;
    doc.hide();
    clock.advance(AUTO_LOCK_HIDDEN_MS);
    doc.show();
    await tick();
    expect(sent).toHaveLength(n);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "signed-out" } });
  });

  it("the 429 wait on the sign-in button is untouched: the same state object, the button still waiting", async () => {
    const { controller, doc, clock, w } = autoSetup();
    w.server.state.optionsRetryAfter = 1800;
    await controller.signIn();
    const waiting = controller.getState();
    expect(waiting.screen === "signed-out" && waiting.retryUntilMs !== undefined).toBe(true);
    doc.hide();
    clock.jump(AUTO_LOCK_HIDDEN_MS);
    doc.show();
    expect(controller.getState()).toBe(waiting);
    const logged = w.server.log.length;
    await controller.signIn(); // still refused locally while the wait runs
    expect(w.server.log.length).toBe(logged);
  });

  it.each(["token", "code"])("an enrolment still at the %s step holds nothing a bystander could complete (a one-time token that still needs the code mailed to the invitee): left alone", (step) => {
    const { calls, doc, clock } = stubController({ screen: "enrol", step });
    doc.hide();
    clock.advance(AUTO_LOCK_HIDDEN_MS);
    doc.show();
    doc.hide();
    clock.jump(AUTO_LOCK_HIDDEN_MS);
    doc.show();
    expect(calls).toEqual([]);
  });
});

describe("auto-lock: what it asks of the controller in each state (stub controller)", () => {
  it("signing in: Cancel, as a keepalive request from the timer (the page is hidden) and a plain one on return; never lock, reset or sign-out", () => {
    const timer = stubController({ screen: "signing-in" });
    timer.doc.hide();
    timer.clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(timer.calls).toEqual(['cancelSignIn {"keepalive":true}']);
    const back = stubController({ screen: "signing-in" });
    back.doc.hide();
    back.clock.jump(AUTO_LOCK_HIDDEN_MS);
    back.doc.show();
    expect(back.calls).toEqual(['cancelSignIn {"keepalive":false}']);
  });

  it("an enrolment at the passkey step: cancelEnrol on both paths, nothing for a hide under the limit", () => {
    const timer = stubController({ screen: "enrol", step: "passkey" });
    timer.doc.hide();
    timer.clock.advance(AUTO_LOCK_HIDDEN_MS - 1);
    expect(timer.calls).toEqual([]);
    timer.clock.advance(1);
    expect(timer.calls).toEqual(['cancelEnrol {"away":true}']);
    const back = stubController({ screen: "enrol", step: "passkey" });
    back.doc.hide();
    back.clock.jump(119_999);
    back.doc.show();
    expect(back.calls).toEqual([]);
    back.doc.hide();
    back.clock.jump(AUTO_LOCK_HIDDEN_MS);
    back.doc.show();
    expect(back.calls).toEqual(['cancelEnrol {"away":true}']);
  });
});

describe("auto-lock while a sign-in is in progress (the OS passkey sheet may hide the page)", () => {
  it.each([200, 119_999])("a hide of %i ms never cancels or disturbs the sign-in: the sheet is answered and the session opens", async (ms) => {
    const { controller, doc, clock, api, sheet, revokes } = autoSetup({ sheet: true });
    const p = controller.signIn();
    await sheet!.isOpen;
    expect(controller.getState().screen).toBe("signing-in");
    doc.hide();
    clock.jump(ms);
    doc.show();
    expect(controller.getState().screen).toBe("signing-in");
    sheet!.release();
    await p;
    expect(controller.getState().screen).toBe("signed-in");
    expect(api.hasSession()).toBe(true);
    expect(revokes()).toEqual([]);
  });

  it("the timer path inside the limit does not touch it either: 119 999 ms of timer time, then the sheet is answered", async () => {
    const { controller, doc, clock, sheet } = autoSetup({ sheet: true });
    const p = controller.signIn();
    await sheet!.isOpen;
    doc.hide();
    clock.advance(119_999);
    expect(controller.getState().screen).toBe("signing-in");
    doc.show();
    sheet!.release();
    await p;
    expect(controller.getState().screen).toBe("signed-in");
  });

  it.each(["return", "timer"] as const)("hidden for the limit while the sheet is open (%s path): the sign-in is cancelled exactly as Cancel does, and no session is opened", async (path) => {
    const { controller, doc, clock, api, sheet, w, sent } = autoSetup({ sheet: true });
    const p = controller.signIn();
    await sheet!.isOpen;
    doc.hide();
    if (path === "return") {
      clock.jump(AUTO_LOCK_HIDDEN_MS);
      doc.show();
    } else clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(controller.getState()).toEqual(CANCELLED); // at once, as Cancel
    await p; // the aborted sheet settles the sign-in
    expect(controller.getState()).toEqual(CANCELLED);
    expect(api.hasSession()).toBe(false);
    expect(w.server.sessions()).toEqual([]);
    expect(sent.filter((r) => r.authorization !== null)).toEqual([]);
  });

  it.each(["return", "timer"] as const)("hidden for the limit while verify is on the wire (%s path): cancelled, and the session the server opens is REVOKED with the new token and never held", async (path) => {
    const hold = holdResponses((u, m) => u.endsWith("/verify") && m === "POST");
    const { controller, doc, clock, api, w, sent } = autoSetup({ wrapFetch: hold.wrap });
    const p = controller.signIn();
    await vi.waitFor(() => expect(hold.pending()).toBe(1));
    doc.hide();
    if (path === "return") {
      clock.jump(AUTO_LOCK_HIDDEN_MS);
      doc.show();
    } else clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(controller.getState()).toEqual(CANCELLED);
    hold.release();
    await p;
    await tick();
    expect(controller.getState()).toEqual(CANCELLED);
    expect(api.hasSession()).toBe(false);
    expect(w.server.issuedTokens).toHaveLength(1);
    expect(w.server.state.revokedSessions.size).toBe(1);
    expect(w.server.sessions()).toEqual([]);
    const revoke = sent.find((r) => r.authorization !== null && /\/sign-out$/.test(r.url));
    expect(revoke?.authorization).toBe(`Bearer ${w.server.issuedTokens[0]}`);
  });
});

describe("auto-lock while a sign-in holds a token that GET session has not yet confirmed (NIT: the revoke of the cancel)", () => {
  it.each([
    ["timer", true],
    ["return", undefined],
  ] as const)("hidden for the limit (%s path): the session already opened is revoked with the OLD token, wiped first, as a keepalive request only from the hidden page", async (path, keepalive) => {
    let armed = false;
    const hold = holdResponses((u, m) => armed && u.endsWith("/session") && m === "GET", { abortable: true });
    const { controller, doc, clock, api, w, sent } = autoSetup({ wrapFetch: hold.wrap });
    armed = true;
    const p = controller.signIn();
    await vi.waitFor(() => expect(hold.pending()).toBe(1)); // verify answered: the token is held, GET session is hanging
    expect(api.hasSession()).toBe(true);
    expect(controller.getState().screen).toBe("signing-in");
    doc.hide();
    if (path === "return") {
      clock.jump(AUTO_LOCK_HIDDEN_MS);
      doc.show();
    } else clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(controller.getState()).toEqual(CANCELLED);
    expect(api.hasSession()).toBe(false);
    await p;
    await tick();
    const revoke = sent.filter((r) => r.authorization !== null && /\/sign-out$/.test(r.url));
    expect(revoke).toHaveLength(1);
    expect(revoke[0]).toMatchObject({ authorization: `Bearer ${w.server.issuedTokens[0]}`, keepalive, hasSessionAtSend: false });
    expect(w.server.state.revokedSessions.size).toBe(1);
  });
});

describe("auto-lock: an enrolment left at the passkey step is not completable by whoever picks the iPad up", () => {
  const EMAIL = "new.hire@partners.example.test";
  const CODE = "123456";

  async function toPasskeyStep(t: ReturnType<typeof autoSetup>) {
    const { token } = t.w.server.addInvite({ email: EMAIL });
    t.controller.startEnrol({ token });
    await t.controller.requestEnrolCode();
    await t.controller.submitEnrolCode(CODE);
    expect(t.controller.getState()).toMatchObject({ screen: "enrol", step: "passkey" });
  }
  const credentialPosts = (t: ReturnType<typeof autoSetup>) => t.sent.filter((r) => r.method === "POST" && r.url.endsWith("/partner-invites/credentials"));

  it.each(["return", "timer"] as const)("hidden for the limit (%s path): back to sign-in, and pressing Create passkey afterwards does nothing: the challenge is gone, no request is sent, no session or credential exists", async (path) => {
    const t = autoSetup();
    await toPasskeyStep(t);
    t.doc.hide();
    if (path === "return") {
      t.clock.jump(AUTO_LOCK_HIDDEN_MS);
      t.doc.show();
    } else t.clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(t.controller.getState()).toEqual(STOPPED_SCREEN);
    await t.controller.createPasskey(); // the button is gone; this is the controller refusing it
    await t.controller.submitEnrolCode(CODE);
    await tick();
    expect(credentialPosts(t)).toEqual([]);
    expect(t.w.server.sessions()).toEqual([]);
    expect(t.w.server.credentialsOf(t.w.server.userByEmail(EMAIL)!.id)).toEqual([]);
    expect(t.api.hasSession()).toBe(false);
  });

  it("the screen says why, in the SAME transition as the cancel: one signed-out state carrying the 'enrolment stopped' notice, never a bare sign-in screen first", async () => {
    const t = autoSetup();
    await toPasskeyStep(t);
    t.states.length = 0;
    t.doc.hide();
    t.clock.jump(AUTO_LOCK_HIDDEN_MS);
    t.doc.show();
    expect(t.states.map((x) => `${x.screen}:${noticeKind(x)}`)).toEqual(["signed-out:enrol-stopped"]);
  });

  it("the notice has its own wording in both languages (not the Lock text, which promises a passkey the invitee does not have yet), and says to ask a manager for a new link", () => {
    expect(noticeText({ kind: "enrol-stopped" }, "en")).toBe("Enrolment stopped because the page was left open. Ask a manager for a new link.");
    expect(noticeText({ kind: "enrol-stopped" }, "fr-CA")).toBe("L'inscription a été interrompue parce que la page est restée ouverte. Demandez un nouveau lien à un gestionnaire.");
    for (const locale of ["en", "fr-CA"] as const) {
      expect(noticeText({ kind: "enrol-stopped" }, locale), locale).not.toBe(noticeText({ kind: "locked-away" }, locale));
      expect(noticeText({ kind: "enrol-stopped" }, locale), locale).not.toBe(noticeText({ kind: "locked" }, locale));
    }
  });

  it("the Back button at this step is the same cancel with no notice (its consequence for the accepted invite is the same; it was always so)", async () => {
    const t = autoSetup();
    await toPasskeyStep(t);
    t.controller.cancelEnrol();
    expect(t.controller.getState()).toEqual({ screen: "signed-out", notice: null });
    const u = autoSetup();
    await toPasskeyStep(u);
    u.controller.cancelEnrol({ away: false });
    expect(u.controller.getState()).toEqual({ screen: "signed-out", notice: null });
  });

  it("a hide of 119 999 ms leaves the enrolment where it was, and Create passkey then completes it (signed in with the forced first PIN)", async () => {
    const t = autoSetup();
    await toPasskeyStep(t);
    t.doc.hide();
    t.clock.jump(119_999);
    t.doc.show();
    expect(t.controller.getState()).toMatchObject({ screen: "enrol", step: "passkey" });
    await t.controller.createPasskey();
    expect(t.controller.getState()).toMatchObject({ screen: "signed-in", panel: { kind: "pin-setup", forced: true } });
  });

  it("the earlier steps are left alone: the same state object after a long hide, and nothing is sent", async () => {
    const t = autoSetup();
    const { token } = t.w.server.addInvite({ email: EMAIL });
    t.controller.startEnrol({ token });
    const atToken = t.controller.getState();
    t.doc.hide();
    t.clock.jump(AUTO_LOCK_HIDDEN_MS);
    t.doc.show();
    expect(t.controller.getState()).toBe(atToken);
    await t.controller.requestEnrolCode();
    const atCode = t.controller.getState();
    expect(atCode).toMatchObject({ step: "code" });
    t.doc.hide();
    t.clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(t.controller.getState()).toBe(atCode);
  });

  it.each(["return", "timer"] as const)("the passkey ceremony is open when the limit passes (%s path): it is aborted, and the credentials request is never sent", async (path) => {
    const t = autoSetup({ createSheet: true });
    await toPasskeyStep(t);
    const p = t.controller.createPasskey();
    await t.createSheet!.isOpen;
    expect(t.controller.getState()).toMatchObject({ screen: "enrol", busy: true });
    t.doc.hide();
    if (path === "return") {
      t.clock.jump(AUTO_LOCK_HIDDEN_MS);
      t.doc.show();
    } else t.clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(t.controller.getState()).toEqual(STOPPED_SCREEN);
    await p;
    t.createSheet!.release(); // the browser answers late: nothing may come of it
    await tick(60);
    expect(credentialPosts(t)).toEqual([]);
    expect(t.w.server.sessions()).toEqual([]);
    expect(t.controller.getState()).toEqual(STOPPED_SCREEN);
  });

  describe.each([
    ["GET session", "/partner-session/session", false],
    ["GET pin", "/partner-session/pin", true],
  ] as const)("P1: the first session is open and %s is still being read when the limit passes", (_name, route, pinReadSent) => {
    it.each(["return", "timer"] as const)("(%s path) the cancel is not undone when the read settles: still signed-out, never signed-in again, and the invitee's session is REVOKED with its own token and never held", async (path) => {
      let armed = false;
      const hold = holdResponses((u, m) => armed && u.endsWith(route) && m === "GET"); // the answer arrives AFTER the cancel (a real fetch would too)
      const t = autoSetup({ wrapFetch: hold.wrap });
      await toPasskeyStep(t);
      armed = true;
      const p = t.controller.createPasskey();
      await vi.waitFor(() => expect(hold.pending()).toBe(1));
      expect(t.controller.getState()).toMatchObject({ screen: "enrol", step: "passkey", busy: true });
      expect(t.api.hasSession()).toBe(true); // registerFirst has adopted the first session
      t.doc.hide();
      if (path === "return") {
        t.clock.jump(AUTO_LOCK_HIDDEN_MS);
        t.doc.show();
      } else t.clock.advance(AUTO_LOCK_HIDDEN_MS);
      expect(t.controller.getState()).toEqual(STOPPED_SCREEN);
      const afterCancel = t.states.length;
      hold.release();
      await p;
      await tick(80);
      expect(t.states.slice(afterCancel).map((x) => x.screen)).toEqual([]); // nothing was drawn after the cancel
      // and a cancelled run asks for nothing more: GET pin was already on the wire in the second case, and is never sent in the first
      expect(t.sent.some((r) => r.method === "GET" && r.url.endsWith("/partner-session/pin"))).toBe(pinReadSent);
      expect(t.controller.getState()).toEqual(STOPPED_SCREEN);
      expect(t.api.hasSession()).toBe(false);
      expect(t.w.server.state.revokedSessions.size).toBe(1);
      expect(t.w.server.sessions()).toEqual([]);
      const revoke = t.sent.filter((r) => r.authorization !== null && /\/sign-out$/.test(r.url));
      expect(revoke).toHaveLength(1);
      expect(revoke[0]).toMatchObject({ authorization: `Bearer ${t.w.server.issuedTokens[0]}`, hasSessionAtSend: false });
    });
  });

  it("the credentials request is already on the wire when the limit passes: cancelled, and the first session the server opens is revoked on arrival and never held", async () => {
    const hold = holdResponses((u, m) => u.endsWith("/partner-invites/credentials") && m === "POST");
    const t = autoSetup({ wrapFetch: hold.wrap });
    await toPasskeyStep(t);
    const p = t.controller.createPasskey();
    await vi.waitFor(() => expect(hold.pending()).toBe(1));
    t.doc.hide();
    t.clock.jump(AUTO_LOCK_HIDDEN_MS);
    t.doc.show();
    expect(t.controller.getState()).toEqual(STOPPED_SCREEN);
    hold.release();
    await p;
    await tick(60);
    expect(t.api.hasSession()).toBe(false);
    expect(t.controller.getState()).toEqual(STOPPED_SCREEN);
    expect(t.w.server.state.revokedSessions.size).toBe(1);
    expect(t.w.server.sessions()).toEqual([]);
  });
});

describe("auto-lock: the other things in flight", () => {
  it("a refresh in flight when the lock fires: the wipe aborts it, and its late result cannot bring the signed-in screen back", async () => {
    let armed = false;
    const hold = holdResponses((u, m) => armed && u.endsWith("/session") && m === "GET", { abortable: true });
    const { controller, doc, clock, api } = autoSetup({ wrapFetch: hold.wrap });
    await controller.signIn(); // signing in reads GET session once; only the refresh after it is held
    armed = true;
    const refreshing = controller.refresh();
    await vi.waitFor(() => expect(hold.pending()).toBe(1));
    doc.hide();
    clock.advance(AUTO_LOCK_HIDDEN_MS);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    expect(hold.signals.at(-1)?.aborted).toBe(true); // the wipe aborted the request that was waiting
    await refreshing;
    hold.release();
    await tick();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    expect(api.hasSession()).toBe(false);
  });

  it("pagehide still revokes with a KEEPALIVE sign-out carrying the old token, and a pending hidden timer does nothing afterwards", async () => {
    const { controller, doc, clock, pagehide, revokes, w, api } = autoSetup();
    await controller.signIn();
    const token = w.server.issuedTokens[0]!;
    doc.hide();
    pagehide();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "expired" } });
    expect(api.hasSession()).toBe(false);
    clock.advance(AUTO_LOCK_HIDDEN_MS * 2);
    doc.show();
    await tick();
    expect(revokes()).toHaveLength(1);
    expect(revokes()[0]).toMatchObject({ url: `${API_BASE}/partner-session/sign-out`, keepalive: true, authorization: `Bearer ${token}` });
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "expired" } });
  });

  it("pageshow with persisted still forces signed-out (and an ordinary pageshow still changes nothing), with the auto-lock installed", async () => {
    const { controller, doc, clock, pageshow, revokes } = autoSetup();
    await controller.signIn();
    doc.hide();
    clock.jump(10_000);
    doc.show();
    pageshow(false);
    expect(controller.getState().screen).toBe("signed-in");
    pageshow(true);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "expired" } });
    await tick();
    expect(revokes()).toHaveLength(1);
  });

  it("a bfcache round trip (pagehide, hidden, then pageshow persisted, visible) leaves one revoke, signed-out, and a visible event that locks nothing", async () => {
    const { controller, doc, clock, pagehide, pageshow, revokes } = autoSetup();
    await controller.signIn();
    pagehide();
    doc.hide();
    clock.jump(AUTO_LOCK_HIDDEN_MS * 3);
    pageshow(true);
    doc.show();
    await tick();
    expect(revokes()).toHaveLength(1);
    expect(controller.getState().screen).toBe("signed-out");
  });
});

describe("auto-lock: the real clock and timers when none are injected", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("the monotonic clock defaults to performance.now(), looked up when used: it alone can lock, with the real wall clock showing next to nothing", async () => {
    const w = makeWorld();
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const doc = new FakeDocument();
    installAutoLock(controller, { document: doc }); // no clock, no timers
    await controller.signIn();
    doc.hide();
    const real = performance.now.bind(performance);
    vi.spyOn(performance, "now").mockImplementation(() => real() + AUTO_LOCK_HIDDEN_MS); // spied AFTER install: a reference taken at load would not see it
    doc.show();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
  });

  it("a page with no performance object cannot prove an absence was brief, so it locks instead of throwing", async () => {
    const w = makeWorld();
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const doc = new FakeDocument();
    installAutoLock(controller, { document: doc });
    await controller.signIn();
    vi.stubGlobal("performance", undefined);
    doc.hide();
    doc.show();
    expect(controller.getState().screen).toBe("signed-out");
  });

  it("defaults to Date.now() and setTimeout, looked up when they are used (so a page-level fake clock, such as Playwright's, drives them)", async () => {
    const w = makeWorld();
    const sent: Array<{ url: string; authorization: string | null }> = [];
    const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
      sent.push({ url: String(input), authorization: new Headers(init?.headers).get("authorization") });
      return w.fetch(input, init);
    }) as typeof fetch;
    const api = createPartnerApi({ baseUrl: API_BASE, fetch: f });
    const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const doc = new FakeDocument();
    installAutoLock(controller, { document: doc }); // no clock, no timers
    await controller.signIn();
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    doc.hide();
    vi.advanceTimersByTime(AUTO_LOCK_HIDDEN_MS - 1);
    expect(controller.getState().screen).toBe("signed-in");
    vi.advanceTimersByTime(1);
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
    vi.useRealTimers();
    await tick();
    expect(sent.filter((r) => r.url.endsWith("/lock"))).toHaveLength(1);
    // and the return path reads the (faked) Date: a second session, hidden, the wall clock moved by two minutes without a timer running
    await controller.signIn();
    vi.useFakeTimers({ toFake: ["Date"] });
    doc.hide();
    vi.setSystemTime(Date.now() + AUTO_LOCK_HIDDEN_MS);
    doc.show();
    expect(controller.getState()).toEqual({ screen: "signed-out", notice: { kind: "locked-away" } });
  });
});
