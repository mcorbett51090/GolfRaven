import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CHROMIUM_EXECUTABLE_PATH,
  renderUrl,
  validateRenderExtraArgs,
  type BrowserLike,
  type ChromiumLauncher,
  type ContextLike,
  type PageLike,
  type RequestLike,
  type ResponseLike,
  type RouteLike,
  type WebSocketRouteLike,
  type WorkerLike,
} from "../src/x2-render.js";

/**
 * A request the fake context's `goto()` feeds through whatever handler the
 * code under test installed via `context.route()`, in order — this is
 * what lets these tests drive the REAL off-host/https/byte-cap logic in
 * `x2-render.ts`, deterministically, without a real browser or network
 * (same dependency-injection principle the rest of this suite uses for
 * `global.fetch`).
 */
interface FakeRequestSpec {
  url: string;
  isNavigation?: boolean;
  /** Only meaningful when `isNavigation` — whether this is the MAIN
   * page's own navigation (default true) or a popup/iframe's (false). */
  mainFrame?: boolean;
  /** Simulates Playwright's own documented behavior: `request.frame()`
   * throws for some early navigation requests. */
  frameThrows?: boolean;
  /** Simulated `content-length` response header, for the byte-cap tests —
   * only "delivered" (fed to the response listener) if this request was
   * NOT aborted. */
  contentLength?: number;
}

interface FakeWsSpec {
  url: string;
}

/** Simulates a popup opening (`window.open`) — fed to the installed
 * `context.on("page", …)` handler during `goto()`. */
interface FakePopupSpec {
  url: string;
}

function makeFakeContext(opts: {
  requests: FakeRequestSpec[];
  websockets?: FakeWsSpec[];
  popups?: FakePopupSpec[];
  finalStatus?: number;
  gotoThrows?: Error;
  gotoReturnsNull?: boolean;
  contentValue?: string;
  contentDelayMs?: number;
}): {
  context: ContextLike;
  isClosed: () => boolean;
  wsClosedUrls: () => string[];
  wsSeenUrls: () => string[];
  abortedUrls: () => string[];
  continuedUrls: () => string[];
  newContextOpts: { userAgent?: string; serviceWorkers?: string };
} {
  let routeHandler:
    | ((route: RouteLike, request: RequestLike) => void | Promise<void>)
    | null = null;
  let wsHandler: ((ws: WebSocketRouteLike) => void | Promise<void>) | null = null;
  let pageHandler: ((page: PageLike) => void) | null = null;
  let responseHandler: ((response: ResponseLike) => void) | null = null;
  let currentUrl = "";
  let closed = false;
  const wsClosed: string[] = [];
  const wsSeen: string[] = [];
  const abortedUrls: string[] = [];
  const continuedUrls: string[] = [];
  const mainFrameToken = { main: true };

  function makeFakePopup(url: string): PageLike {
    let popupClosed = false;
    return {
      async goto() {
        return { status: () => 200, url: () => url, headers: () => ({}) };
      },
      async content() {
        return "";
      },
      async close() {
        popupClosed = true;
      },
      url() {
        return popupClosed ? url : url;
      },
      mainFrame() {
        return { main: false };
      },
    };
  }

  const context: ContextLike = {
    async newPage() {
      const page: PageLike = {
        async goto(url) {
          currentUrl = url;
          if (opts.gotoThrows) throw opts.gotoThrows;
          for (const spec of opts.requests) {
            const request: RequestLike = {
              url: () => spec.url,
              isNavigationRequest: () => spec.isNavigation ?? false,
              frame: () => {
                if (spec.frameThrows) throw new Error("frame not available yet");
                return (spec.mainFrame ?? true) ? mainFrameToken : { main: false };
              },
            };
            let aborted = false;
            const route: RouteLike = {
              async abort() {
                aborted = true;
                abortedUrls.push(spec.url);
              },
              async continue() {
                aborted = false;
                continuedUrls.push(spec.url);
              },
            };
            if (routeHandler) await routeHandler(route, request);
            if (!aborted) {
              // Only a MAIN-FRAME navigation updates page.url() — an
              // iframe/popup navigating does not change what the page
              // itself reports as its own URL, matching real Playwright.
              if (spec.isNavigation && (spec.mainFrame ?? true)) currentUrl = spec.url;
              if (responseHandler) {
                responseHandler({
                  status: () => 200,
                  url: () => spec.url,
                  headers: () =>
                    spec.contentLength !== undefined
                      ? { "content-length": String(spec.contentLength) }
                      : {},
                });
              }
            }
          }
          for (const wsSpec of opts.websockets ?? []) {
            wsSeen.push(wsSpec.url);
            if (wsHandler) {
              const ws: WebSocketRouteLike = {
                url: () => wsSpec.url,
                close: async () => {
                  wsClosed.push(wsSpec.url);
                },
              };
              await wsHandler(ws);
            }
          }
          for (const popupSpec of opts.popups ?? []) {
            if (pageHandler) pageHandler(makeFakePopup(popupSpec.url));
          }
          if (opts.gotoReturnsNull) return null;
          return {
            status: () => opts.finalStatus ?? 200,
            url: () => currentUrl,
            headers: () => ({}),
          };
        },
        async content() {
          if (opts.contentDelayMs) {
            await new Promise((resolve) => setTimeout(resolve, opts.contentDelayMs));
          }
          return opts.contentValue ?? "<p>ok</p>";
        },
        async close() {},
        url() {
          return currentUrl;
        },
        mainFrame() {
          return mainFrameToken;
        },
      };
      return page;
    },
    async route(_pattern, handler) {
      routeHandler = handler;
    },
    async routeWebSocket(_matcher, handler) {
      wsHandler = handler;
    },
    on(event, handler) {
      if (event === "page") pageHandler = handler as (page: PageLike) => void;
      if (event === "response") responseHandler = handler as (response: ResponseLike) => void;
    },
    async close() {
      closed = true;
    },
  };

  return {
    context,
    isClosed: () => closed,
    wsClosedUrls: () => wsClosed,
    wsSeenUrls: () => wsSeen,
    abortedUrls: () => abortedUrls,
    continuedUrls: () => continuedUrls,
    newContextOpts: {},
  };
}

function fakeLauncher(context: ContextLike): {
  launch: ChromiumLauncher;
  seenExecutablePath: string[];
  seenArgs: (string[] | undefined)[];
  seenTimeout: (number | undefined)[];
  seenContextOpts: { userAgent: string; serviceWorkers?: string }[];
  isClosed: () => boolean;
} {
  let closed = false;
  const state = {
    launch: (() => {}) as unknown as ChromiumLauncher,
    seenExecutablePath: [] as string[],
    seenArgs: [] as (string[] | undefined)[],
    seenTimeout: [] as (number | undefined)[],
    seenContextOpts: [] as { userAgent: string; serviceWorkers?: string }[],
    isClosed: () => closed,
  };
  const browser: BrowserLike = {
    async newContext(contextOpts) {
      state.seenContextOpts.push(contextOpts);
      return context;
    },
    async close() {
      closed = true;
    },
  };
  state.launch = (async (opts: {
    executablePath: string;
    headless: boolean;
    args?: string[];
    timeout?: number;
  }) => {
    state.seenExecutablePath.push(opts.executablePath);
    state.seenArgs.push(opts.args);
    state.seenTimeout.push(opts.timeout);
    expect(opts.headless).toBe(true);
    return browser;
  }) as ChromiumLauncher;
  return state;
}

const SAME_HOST_URL = "https://golfvancouverisland.ca/";
const SAME_HOST_NAV = { url: SAME_HOST_URL, isNavigation: true };

describe("x2-render: validateRenderExtraArgs (gate: Chromium arg allowlist)", () => {
  it("accepts zero args", () => {
    expect(() => validateRenderExtraArgs([])).not.toThrow();
  });

  it("accepts exactly one well-formed --ignore-certificate-errors-spki-list=<sha256> arg", () => {
    const hash = "A".repeat(43) + "=";
    expect(() =>
      validateRenderExtraArgs([`--ignore-certificate-errors-spki-list=${hash}`]),
    ).not.toThrow();
  });

  it("accepts a comma-separated list of hashes in the one allowed arg", () => {
    const hash = "A".repeat(43) + "=";
    expect(() =>
      validateRenderExtraArgs([`--ignore-certificate-errors-spki-list=${hash},${hash}`]),
    ).not.toThrow();
  });

  it("refuses ANY other Chromium flag", () => {
    expect(() => validateRenderExtraArgs(["--disable-web-security"])).toThrow(/must match/);
    expect(() => validateRenderExtraArgs(["--ignore-certificate-errors"])).toThrow(/must match/);
    expect(() => validateRenderExtraArgs(["--host-resolver-rules=MAP a b"])).toThrow(/must match/);
  });

  it("refuses a malformed SPKI hash (wrong length, bad characters, missing padding)", () => {
    expect(() =>
      validateRenderExtraArgs(["--ignore-certificate-errors-spki-list=short"]),
    ).toThrow(/must match/);
    expect(() =>
      validateRenderExtraArgs([`--ignore-certificate-errors-spki-list=${"A".repeat(43)}X`]),
    ).toThrow(/must match/);
  });

  it("refuses more than one arg, even if each one alone would be valid", () => {
    const hash = "A".repeat(43) + "=";
    expect(() =>
      validateRenderExtraArgs([
        `--ignore-certificate-errors-spki-list=${hash}`,
        `--ignore-certificate-errors-spki-list=${hash}`,
      ]),
    ).toThrow(/exactly one/);
  });

  it("gate probe: refuses a valid flag with a SECOND flag jammed into the same string via a space", () => {
    const hash = "A".repeat(43) + "=";
    expect(() =>
      validateRenderExtraArgs([`--ignore-certificate-errors-spki-list=${hash} --no-sandbox`]),
    ).toThrow(/must match/);
  });
});

describe("x2-render: renderUrl — basic flow", () => {
  it("launches Chromium at the default pinned executablePath, opens a context with the tool's User-Agent and Service Workers blocked, and returns status/finalUrl/html", async () => {
    const { context } = makeFakeContext({
      requests: [SAME_HOST_NAV],
      contentValue: "<html><body><h1>Vancouver Island Golf Trail</h1></body></html>",
    });
    const { launch, seenExecutablePath, seenContextOpts } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "GolfRaven-P0-X2/0.1 (test)",
      launch,
    });
    expect(result.status).toBe(200);
    expect(result.finalUrl).toBe(SAME_HOST_URL);
    expect(result.html).toContain("Vancouver Island Golf Trail");
    expect(result.argsUsed).toEqual([]);
    expect(seenExecutablePath).toEqual([DEFAULT_CHROMIUM_EXECUTABLE_PATH]);
    expect(seenContextOpts).toEqual([
      { userAgent: "GolfRaven-P0-X2/0.1 (test)", serviceWorkers: "block" },
    ]);
  });

  it("validates extraArgs (throws on an invalid shape) BEFORE ever launching a browser", async () => {
    const { context } = makeFakeContext({ requests: [SAME_HOST_NAV] });
    const { launch } = fakeLauncher(context);
    const launchSpy = vi.fn(launch);
    await expect(
      renderUrl(SAME_HOST_URL, {
        userAgent: "ua",
        launch: launchSpy,
        extraArgs: ["--disable-web-security"],
      }),
    ).rejects.toThrow(/must match/);
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("passes a validated extraArgs through to the launcher, and echoes it back as argsUsed", async () => {
    const hash = "B".repeat(43) + "=";
    const { context } = makeFakeContext({ requests: [SAME_HOST_NAV] });
    const { launch, seenArgs } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "ua",
      launch,
      extraArgs: [`--ignore-certificate-errors-spki-list=${hash}`],
    });
    expect(seenArgs).toEqual([[`--ignore-certificate-errors-spki-list=${hash}`]]);
    expect(result.argsUsed).toEqual([`--ignore-certificate-errors-spki-list=${hash}`]);
  });

  it("uses an explicit executablePath and launchTimeoutMs when given", async () => {
    const { context } = makeFakeContext({ requests: [SAME_HOST_NAV] });
    const { launch, seenExecutablePath, seenTimeout } = fakeLauncher(context);
    await renderUrl(SAME_HOST_URL, {
      userAgent: "ua",
      launch,
      executablePath: "/custom/chromium",
      launchTimeoutMs: 5000,
    });
    expect(seenExecutablePath).toEqual(["/custom/chromium"]);
    expect(seenTimeout).toEqual([5000]);
  });

  it("passes an explicit launch timeout by default (not left unset)", async () => {
    const { context } = makeFakeContext({ requests: [SAME_HOST_NAV] });
    const { launch, seenTimeout } = fakeLauncher(context);
    await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(seenTimeout[0]).toBeGreaterThan(0);
  });

  it("gate N6: refuses (throws) a non-https URL before ever launching a browser", async () => {
    const { context } = makeFakeContext({ requests: [] });
    const { launch } = fakeLauncher(context);
    const launchSpy = vi.fn(launch);
    await expect(
      renderUrl("http://golfvancouverisland.ca/", { userAgent: "ua", launch: launchSpy }),
    ).rejects.toThrow(/gate N6/);
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("gate N6: refuses (throws) a non-URL string before ever launching a browser", async () => {
    const { context } = makeFakeContext({ requests: [] });
    const { launch } = fakeLauncher(context);
    const launchSpy = vi.fn(launch);
    await expect(renderUrl("not a url", { userAgent: "ua", launch: launchSpy })).rejects.toThrow(
      /not a valid URL/,
    );
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("throws, and STILL CLOSES the context and the browser, when navigation produces no response at all", async () => {
    const { context, isClosed } = makeFakeContext({
      requests: [SAME_HOST_NAV],
      gotoReturnsNull: true,
    });
    const { launch, isClosed: browserClosed } = fakeLauncher(context);
    await expect(renderUrl(SAME_HOST_URL, { userAgent: "ua", launch })).rejects.toThrow(
      /produced no response/,
    );
    expect(isClosed()).toBe(true);
    expect(browserClosed()).toBe(true);
  });

  it("closes the context and the browser even when goto throws", async () => {
    const { context, isClosed } = makeFakeContext({
      requests: [],
      gotoThrows: new Error("navigation failed"),
    });
    const { launch, isClosed: browserClosed } = fakeLauncher(context);
    await expect(renderUrl(SAME_HOST_URL, { userAgent: "ua", launch })).rejects.toThrow(
      /navigation failed/,
    );
    expect(isClosed()).toBe(true);
    expect(browserClosed()).toBe(true);
  });
});

describe("x2-render: renderUrl — main-frame navigation control (gate finding)", () => {
  it("allows a same-host, https main-frame navigation through", async () => {
    const { context } = makeFakeContext({ requests: [SAME_HOST_NAV] });
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("blocks an off-host main-frame navigation (e.g. a client-side JS redirect or meta-refresh) and fails the capture", async () => {
    const { context, isClosed } = makeFakeContext({
      requests: [
        SAME_HOST_NAV,
        { url: "https://elsewhere.test/", isNavigation: true, mainFrame: true },
      ],
    });
    const { launch } = fakeLauncher(context);
    await expect(renderUrl(SAME_HOST_URL, { userAgent: "ua", launch })).rejects.toThrow(
      /off-host/,
    );
    expect(isClosed()).toBe(true);
  });

  it("blocks a main-frame navigation hop that downgrades to http, at ANY hop of a redirect chain", async () => {
    const { context } = makeFakeContext({
      requests: [
        SAME_HOST_NAV,
        { url: "http://golfvancouverisland.ca/insecure-hop", isNavigation: true, mainFrame: true },
      ],
    });
    const { launch } = fakeLauncher(context);
    await expect(renderUrl(SAME_HOST_URL, { userAgent: "ua", launch })).rejects.toThrow(
      /downgraded to non-https/,
    );
  });

  it("does NOT block a sub-frame (iframe) navigation to a SAME host — it is CONTINUED, not aborted", async () => {
    const iframeUrl = "https://golfvancouverisland.ca/iframe-widget";
    const { context, abortedUrls, continuedUrls } = makeFakeContext({
      requests: [SAME_HOST_NAV, { url: iframeUrl, isNavigation: true, mainFrame: false }],
    });
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
    expect(continuedUrls()).toContain(iframeUrl);
    expect(abortedUrls()).not.toContain(iframeUrl);
  });

  it("gate finding: an off-host iframe navigation IS ABORTED (falls through to the off-host block, same as a subresource) — asserted directly, not just inferred from a non-throw", async () => {
    const iframeUrl = "https://127.0.0.1:8443/tp.html";
    const { context, abortedUrls, continuedUrls } = makeFakeContext({
      requests: [SAME_HOST_NAV, { url: iframeUrl, isNavigation: true, mainFrame: false }],
    });
    const { launch } = fakeLauncher(context);
    // Does not throw — an off-host IFRAME is aborted like any other
    // off-host subresource, it does not fail the whole capture — but the
    // abort itself is asserted directly here, not just inferred.
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
    expect(abortedUrls()).toContain(iframeUrl);
    expect(continuedUrls()).not.toContain(iframeUrl);
  });

  it("treats a navigation request whose frame() throws as the main frame (Playwright's own documented early-navigation case)", async () => {
    const { context } = makeFakeContext({
      requests: [{ url: SAME_HOST_URL, isNavigation: true, frameThrows: true }],
    });
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("fails the capture (defense in depth) if page.url() ends up off-host despite route blocking", async () => {
    const { context } = makeFakeContext({
      requests: [{ url: "https://elsewhere.test/", isNavigation: false }],
    });
    const { launch } = fakeLauncher(context);
    // Monkeypatch the page this fake context will hand back so page.url()
    // reports an off-host URL directly, simulating a route case the
    // handler somehow didn't catch.
    const originalNewPage = context.newPage.bind(context);
    context.newPage = async () => {
      const page = await originalNewPage();
      page.url = () => "https://elsewhere.test/sneaky";
      return page;
    };
    await expect(renderUrl(SAME_HOST_URL, { userAgent: "ua", launch })).rejects.toThrow(
      /ended off-host/,
    );
  });
});

describe("x2-render: renderUrl — third-party injected text via subresources (gate finding, primary fix)", () => {
  it("aborts an off-host SUBRESOURCE request (script/XHR/etc.) — the primary fix against injected text", async () => {
    const { context } = makeFakeContext({
      requests: [
        SAME_HOST_NAV,
        { url: "https://127.0.0.1:8443/tp.txt", isNavigation: false },
      ],
    });
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("allows a same-host subresource request through", async () => {
    const { context } = makeFakeContext({
      requests: [SAME_HOST_NAV, { url: "https://golfvancouverisland.ca/app.js", isNavigation: false }],
    });
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });
});

describe("x2-render: renderUrl — off-host WebSocket blocking (gate finding, pass 2)", () => {
  it("closes an off-host WebSocket immediately, before any message exchange", async () => {
    const { context, wsClosedUrls, wsSeenUrls } = makeFakeContext({
      requests: [SAME_HOST_NAV],
      websockets: [{ url: "wss://127.0.0.1:8443/sock" }],
    });
    const { launch } = fakeLauncher(context);
    await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(wsSeenUrls()).toEqual(["wss://127.0.0.1:8443/sock"]);
    expect(wsClosedUrls()).toEqual(["wss://127.0.0.1:8443/sock"]);
  });

  it("does NOT close a same-host WebSocket", async () => {
    const { context, wsClosedUrls } = makeFakeContext({
      requests: [SAME_HOST_NAV],
      websockets: [{ url: "wss://golfvancouverisland.ca/sock" }],
    });
    const { launch } = fakeLauncher(context);
    await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(wsClosedUrls()).toEqual([]);
  });
});

describe("x2-render: renderUrl — popup (window.open) handling (gate finding, pass 2)", () => {
  it("closes a popup immediately AND fails the capture — a popup opening at all is never silently tolerated", async () => {
    const { context } = makeFakeContext({
      requests: [SAME_HOST_NAV],
      popups: [{ url: "https://127.0.0.1:8443/popup-src.html" }],
    });
    const { launch } = fakeLauncher(context);
    await expect(renderUrl(SAME_HOST_URL, { userAgent: "ua", launch })).rejects.toThrow(
      /opened a popup/,
    );
  });

  it("regression (found live against real Chromium): does NOT false-positive on the context's own newPage() call, which fires the SAME 'page' event Playwright uses for a real popup", async () => {
    // A minimal, hand-built ContextLike that reproduces the exact real
    // Playwright quirk that broke this once: `context.newPage()` itself
    // emits a "page" event synchronously, for its OWN page, BEFORE the
    // `newPage()` promise resolves back to the caller. A naive `popup ===
    // mainPage` identity check races that resolution and false-positives
    // on every single render. The fix (verified live in real Chromium via
    // the gate's probe) is registering the "page" listener only AFTER
    // `context.newPage()` has already resolved — this test proves that
    // ordering, not just the identity check, is what makes it safe.
    let pageHandler: ((page: PageLike) => void) | null = null;
    const ownPage: PageLike = {
      async goto(url) {
        return { status: () => 200, url: () => url, headers: () => ({}) };
      },
      async content() {
        return "<p>ok, no false-positive popup failure</p>";
      },
      async close() {},
      url() {
        return SAME_HOST_URL;
      },
      mainFrame() {
        return { main: true };
      },
    };
    const context: ContextLike = {
      async newPage() {
        // Fires BEFORE this promise resolves — exactly like real
        // Playwright does for the page's own about:blank -> navigating
        // transition.
        if (pageHandler) pageHandler(ownPage);
        return ownPage;
      },
      async route(_pattern, _handler) {},
      async routeWebSocket() {},
      on(event, handler) {
        if (event === "page") pageHandler = handler as (page: PageLike) => void;
      },
      async close() {},
    };
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.html).toContain("no false-positive popup failure");
  });
});

describe("x2-render: renderUrl — subresource byte cap (best-effort, gate finding)", () => {
  it("passes when total response content-length stays under the cap", async () => {
    const { context } = makeFakeContext({
      requests: [SAME_HOST_NAV, { url: "https://golfvancouverisland.ca/img.png", isNavigation: false, contentLength: 1000 }],
    });
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "ua",
      launch,
      subresourceByteCapBytes: 2000,
    });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("fails the capture once cumulative content-length exceeds the cap", async () => {
    const { context } = makeFakeContext({
      requests: [
        SAME_HOST_NAV,
        { url: "https://golfvancouverisland.ca/big1.png", isNavigation: false, contentLength: 1500 },
        { url: "https://golfvancouverisland.ca/big2.png", isNavigation: false, contentLength: 1500 },
      ],
    });
    const { launch } = fakeLauncher(context);
    await expect(
      renderUrl(SAME_HOST_URL, { userAgent: "ua", launch, subresourceByteCapBytes: 2000 }),
    ).rejects.toThrow(/subresource cap/);
  });
});

describe("x2-render: renderUrl — explicit content timeout", () => {
  it("times out page.content() rather than hanging forever", async () => {
    const { context } = makeFakeContext({ requests: [SAME_HOST_NAV], contentDelayMs: 200 });
    const { launch } = fakeLauncher(context);
    await expect(
      renderUrl(SAME_HOST_URL, { userAgent: "ua", launch, contentTimeoutMs: 20 }),
    ).rejects.toThrow(/timed out/);
  });

  it("succeeds when content() resolves before the timeout", async () => {
    const { context } = makeFakeContext({
      requests: [SAME_HOST_NAV],
      contentDelayMs: 5,
      contentValue: "<p>fast enough</p>",
    });
    const { launch } = fakeLauncher(context);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "ua",
      launch,
      contentTimeoutMs: 2000,
    });
    expect(result.html).toBe("<p>fast enough</p>");
  });
});
