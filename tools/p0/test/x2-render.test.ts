import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CHROMIUM_EXECUTABLE_PATH,
  renderUrl,
  validateRenderExtraArgs,
  type BrowserLike,
  type ChromiumLauncher,
  type PageLike,
  type RequestLike,
  type ResponseLike,
  type RouteLike,
} from "../src/x2-render.js";

/**
 * A request the fake page's `goto()` feeds through whatever handler the
 * code under test installed via `page.route()`, in order — this is what
 * lets these tests drive the REAL off-host/https/byte-cap logic in
 * `x2-render.ts`, deterministically, without a real browser or network
 * (same dependency-injection principle the rest of this suite uses for
 * `global.fetch`).
 */
interface FakeRequestSpec {
  url: string;
  isNavigation?: boolean;
  /** Only meaningful when `isNavigation` — whether this is the MAIN
   * frame's own navigation (default true) or a sub-frame's (false). */
  mainFrame?: boolean;
  /** Simulates Playwright's own documented behavior: `request.frame()`
   * throws for some early navigation requests. */
  frameThrows?: boolean;
  /** Simulated `content-length` response header, for the byte-cap tests —
   * only "delivered" (fed to the response listener) if this request was
   * NOT aborted. */
  contentLength?: number;
}

function makeFakePage(opts: {
  requests: FakeRequestSpec[];
  finalStatus?: number;
  gotoThrows?: Error;
  gotoReturnsNull?: boolean;
  contentValue?: string;
  contentDelayMs?: number;
}): {
  page: PageLike;
  isClosed: () => boolean;
  headersSeen: () => Record<string, string> | null;
} {
  let routeHandler:
    ((route: RouteLike, request: RequestLike) => void | Promise<void>) | null =
    null;
  let responseHandler: ((response: ResponseLike) => void) | null = null;
  let currentUrl = "";
  let closed = false;
  let headers: Record<string, string> | null = null;
  const mainFrameToken = { main: true };
  const subFrameToken = { main: false };

  const page: PageLike = {
    async setExtraHTTPHeaders(h) {
      headers = h;
    },
    async route(_pattern, handler) {
      routeHandler = handler;
    },
    on(event, handler) {
      if (event === "response") responseHandler = handler;
    },
    mainFrame() {
      return mainFrameToken;
    },
    url() {
      return currentUrl;
    },
    async goto(url) {
      currentUrl = url;
      if (opts.gotoThrows) throw opts.gotoThrows;
      for (const spec of opts.requests) {
        const request: RequestLike = {
          url: () => spec.url,
          isNavigationRequest: () => spec.isNavigation ?? false,
          frame: () => {
            if (spec.frameThrows) throw new Error("frame not available yet");
            return (spec.mainFrame ?? true) ? mainFrameToken : subFrameToken;
          },
        };
        let aborted = false;
        const route: RouteLike = {
          async abort() {
            aborted = true;
          },
          async continue() {
            aborted = false;
          },
        };
        if (routeHandler) await routeHandler(route, request);
        if (!aborted) {
          if (spec.isNavigation) currentUrl = spec.url;
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
      if (opts.gotoReturnsNull) return null;
      return {
        status: () => opts.finalStatus ?? 200,
        url: () => currentUrl,
        headers: () => ({}),
      };
    },
    async content() {
      if (opts.contentDelayMs) {
        await new Promise((resolve) =>
          setTimeout(resolve, opts.contentDelayMs),
        );
      }
      return opts.contentValue ?? "<p>ok</p>";
    },
    async close() {
      closed = true;
    },
  };
  return { page, isClosed: () => closed, headersSeen: () => headers };
}

function fakeLauncher(page: PageLike): {
  launch: ChromiumLauncher;
  seenExecutablePath: string[];
  seenArgs: (string[] | undefined)[];
  seenTimeout: (number | undefined)[];
  isClosed: () => boolean;
} {
  let closed = false;
  const state = {
    launch: (() => {}) as unknown as ChromiumLauncher,
    seenExecutablePath: [] as string[],
    seenArgs: [] as (string[] | undefined)[],
    seenTimeout: [] as (number | undefined)[],
    isClosed: () => closed,
  };
  const browser: BrowserLike = {
    async newPage() {
      return page;
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
      validateRenderExtraArgs([
        `--ignore-certificate-errors-spki-list=${hash}`,
      ]),
    ).not.toThrow();
  });

  it("accepts a comma-separated list of hashes in the one allowed arg", () => {
    const hash = "A".repeat(43) + "=";
    expect(() =>
      validateRenderExtraArgs([
        `--ignore-certificate-errors-spki-list=${hash},${hash}`,
      ]),
    ).not.toThrow();
  });

  it("refuses ANY other Chromium flag", () => {
    expect(() => validateRenderExtraArgs(["--disable-web-security"])).toThrow(
      /must match/,
    );
    expect(() =>
      validateRenderExtraArgs(["--ignore-certificate-errors"]),
    ).toThrow(/must match/);
    expect(() =>
      validateRenderExtraArgs(["--host-resolver-rules=MAP a b"]),
    ).toThrow(/must match/);
  });

  it("refuses a malformed SPKI hash (wrong length, bad characters, missing padding)", () => {
    expect(() =>
      validateRenderExtraArgs(["--ignore-certificate-errors-spki-list=short"]),
    ).toThrow(/must match/);
    expect(() =>
      validateRenderExtraArgs([
        `--ignore-certificate-errors-spki-list=${"A".repeat(43)}X`,
      ]),
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
});

describe("x2-render: renderUrl — basic flow", () => {
  it("launches Chromium at the default pinned executablePath, sets the User-Agent, and returns status/finalUrl/html", async () => {
    const { page, headersSeen } = makeFakePage({
      requests: [SAME_HOST_NAV],
      contentValue:
        "<html><body><h1>Vancouver Island Golf Trail</h1></body></html>",
    });
    const { launch, seenExecutablePath } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "GolfRaven-P0-X2/0.1 (test)",
      launch,
    });
    expect(result.status).toBe(200);
    expect(result.finalUrl).toBe(SAME_HOST_URL);
    expect(result.html).toContain("Vancouver Island Golf Trail");
    expect(result.argsUsed).toEqual([]);
    expect(seenExecutablePath).toEqual([DEFAULT_CHROMIUM_EXECUTABLE_PATH]);
    expect(headersSeen()).toEqual({
      "User-Agent": "GolfRaven-P0-X2/0.1 (test)",
    });
  });

  it("validates extraArgs (throws on an invalid shape) BEFORE ever launching a browser", async () => {
    const { page } = makeFakePage({ requests: [SAME_HOST_NAV] });
    const { launch } = fakeLauncher(page);
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
    const { page } = makeFakePage({ requests: [SAME_HOST_NAV] });
    const { launch, seenArgs } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "ua",
      launch,
      extraArgs: [`--ignore-certificate-errors-spki-list=${hash}`],
    });
    expect(seenArgs).toEqual([
      [`--ignore-certificate-errors-spki-list=${hash}`],
    ]);
    expect(result.argsUsed).toEqual([
      `--ignore-certificate-errors-spki-list=${hash}`,
    ]);
  });

  it("uses an explicit executablePath and launchTimeoutMs when given", async () => {
    const { page } = makeFakePage({ requests: [SAME_HOST_NAV] });
    const { launch, seenExecutablePath, seenTimeout } = fakeLauncher(page);
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
    const { page } = makeFakePage({ requests: [SAME_HOST_NAV] });
    const { launch, seenTimeout } = fakeLauncher(page);
    await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(seenTimeout[0]).toBeGreaterThan(0);
  });

  it("gate N6: refuses (throws) a non-https URL before ever launching a browser", async () => {
    const { page } = makeFakePage({ requests: [] });
    const { launch } = fakeLauncher(page);
    const launchSpy = vi.fn(launch);
    await expect(
      renderUrl("http://golfvancouverisland.ca/", {
        userAgent: "ua",
        launch: launchSpy,
      }),
    ).rejects.toThrow(/gate N6/);
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("gate N6: refuses (throws) a non-URL string before ever launching a browser", async () => {
    const { page } = makeFakePage({ requests: [] });
    const { launch } = fakeLauncher(page);
    const launchSpy = vi.fn(launch);
    await expect(
      renderUrl("not a url", { userAgent: "ua", launch: launchSpy }),
    ).rejects.toThrow(/not a valid URL/);
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("throws, and STILL CLOSES the page and the browser, when navigation produces no response at all", async () => {
    const { page, isClosed } = makeFakePage({
      requests: [SAME_HOST_NAV],
      gotoReturnsNull: true,
    });
    const { launch, isClosed: browserClosed } = fakeLauncher(page);
    await expect(
      renderUrl(SAME_HOST_URL, { userAgent: "ua", launch }),
    ).rejects.toThrow(/produced no response/);
    expect(isClosed()).toBe(true);
    expect(browserClosed()).toBe(true);
  });

  it("closes the page and the browser even when goto throws", async () => {
    const { page, isClosed } = makeFakePage({
      requests: [],
      gotoThrows: new Error("navigation failed"),
    });
    const { launch, isClosed: browserClosed } = fakeLauncher(page);
    await expect(
      renderUrl(SAME_HOST_URL, { userAgent: "ua", launch }),
    ).rejects.toThrow(/navigation failed/);
    expect(isClosed()).toBe(true);
    expect(browserClosed()).toBe(true);
  });
});

describe("x2-render: renderUrl — main-frame navigation control (gate finding)", () => {
  it("allows a same-host, https main-frame navigation through", async () => {
    const { page } = makeFakePage({ requests: [SAME_HOST_NAV] });
    const { launch } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("blocks an off-host main-frame navigation (e.g. a client-side JS redirect) and fails the capture", async () => {
    const { page, isClosed } = makeFakePage({
      requests: [
        SAME_HOST_NAV,
        { url: "https://elsewhere.test/", isNavigation: true, mainFrame: true },
      ],
    });
    const { launch } = fakeLauncher(page);
    await expect(
      renderUrl(SAME_HOST_URL, { userAgent: "ua", launch }),
    ).rejects.toThrow(/off-host/);
    expect(isClosed()).toBe(true);
  });

  it("blocks a main-frame navigation hop that downgrades to http, at ANY hop of a redirect chain", async () => {
    const { page } = makeFakePage({
      requests: [
        SAME_HOST_NAV,
        {
          url: "http://golfvancouverisland.ca/insecure-hop",
          isNavigation: true,
          mainFrame: true,
        },
      ],
    });
    const { launch } = fakeLauncher(page);
    await expect(
      renderUrl(SAME_HOST_URL, { userAgent: "ua", launch }),
    ).rejects.toThrow(/downgraded to non-https/);
  });

  it("does NOT block a sub-frame (iframe) navigation to a different host — only MAIN-frame navigation is host-restricted", async () => {
    const { page } = makeFakePage({
      requests: [
        SAME_HOST_NAV,
        {
          url: "https://embedded-widget.test/iframe",
          isNavigation: true,
          mainFrame: false,
        },
      ],
    });
    const { launch } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    // The main frame itself never left the requested host.
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("treats a navigation request whose frame() throws as the main frame (Playwright's own documented early-navigation case)", async () => {
    const { page } = makeFakePage({
      requests: [{ url: SAME_HOST_URL, isNavigation: true, frameThrows: true }],
    });
    const { launch } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("fails the capture (defense in depth) if page.url() ends up off-host despite route blocking", async () => {
    // Simulate the route handler somehow not catching it (e.g. a future
    // navigation shape it doesn't recognize) — the post-hoc page.url()
    // check is the fallback that still catches this.
    const { page } = makeFakePage({
      requests: [{ url: "https://elsewhere.test/", isNavigation: false }],
    });
    // Force page.url() to report an off-host URL directly.
    page.url = () => "https://elsewhere.test/sneaky";
    const { launch } = fakeLauncher(page);
    await expect(
      renderUrl(SAME_HOST_URL, { userAgent: "ua", launch }),
    ).rejects.toThrow(/ended off-host/);
  });
});

describe("x2-render: renderUrl — third-party injected text (gate finding, primary fix)", () => {
  it("aborts an off-host SUBRESOURCE request (script/XHR/etc.) — the primary fix against injected text", async () => {
    const { page } = makeFakePage({
      requests: [
        SAME_HOST_NAV,
        { url: "https://thirdparty.test/inject.js", isNavigation: false },
      ],
    });
    const { launch } = fakeLauncher(page);
    // Should not throw — off-host subresources are silently aborted, not a
    // capture failure (only off-host MAIN-FRAME navigation fails the run).
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("allows a same-host subresource request through", async () => {
    const { page } = makeFakePage({
      requests: [
        SAME_HOST_NAV,
        { url: "https://golfvancouverisland.ca/app.js", isNavigation: false },
      ],
    });
    const { launch } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, { userAgent: "ua", launch });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });
});

describe("x2-render: renderUrl — subresource byte cap (best-effort, gate finding)", () => {
  it("passes when total response content-length stays under the cap", async () => {
    const { page } = makeFakePage({
      requests: [
        SAME_HOST_NAV,
        {
          url: "https://golfvancouverisland.ca/img.png",
          isNavigation: false,
          contentLength: 1000,
        },
      ],
    });
    const { launch } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "ua",
      launch,
      subresourceByteCapBytes: 2000,
    });
    expect(result.finalUrl).toBe(SAME_HOST_URL);
  });

  it("fails the capture once cumulative content-length exceeds the cap", async () => {
    const { page } = makeFakePage({
      requests: [
        SAME_HOST_NAV,
        {
          url: "https://golfvancouverisland.ca/big1.png",
          isNavigation: false,
          contentLength: 1500,
        },
        {
          url: "https://golfvancouverisland.ca/big2.png",
          isNavigation: false,
          contentLength: 1500,
        },
      ],
    });
    const { launch } = fakeLauncher(page);
    await expect(
      renderUrl(SAME_HOST_URL, {
        userAgent: "ua",
        launch,
        subresourceByteCapBytes: 2000,
      }),
    ).rejects.toThrow(/subresource cap/);
  });
});

describe("x2-render: renderUrl — explicit content timeout", () => {
  it("times out page.content() rather than hanging forever", async () => {
    const { page } = makeFakePage({
      requests: [SAME_HOST_NAV],
      contentDelayMs: 200,
    });
    const { launch } = fakeLauncher(page);
    await expect(
      renderUrl(SAME_HOST_URL, {
        userAgent: "ua",
        launch,
        contentTimeoutMs: 20,
      }),
    ).rejects.toThrow(/timed out/);
  });

  it("succeeds when content() resolves before the timeout", async () => {
    const { page } = makeFakePage({
      requests: [SAME_HOST_NAV],
      contentDelayMs: 5,
      contentValue: "<p>fast enough</p>",
    });
    const { launch } = fakeLauncher(page);
    const result = await renderUrl(SAME_HOST_URL, {
      userAgent: "ua",
      launch,
      contentTimeoutMs: 2000,
    });
    expect(result.html).toBe("<p>fast enough</p>");
  });
});
