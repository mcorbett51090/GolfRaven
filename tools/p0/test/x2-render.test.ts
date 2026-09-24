import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CHROMIUM_EXECUTABLE_PATH,
  renderUrl,
  type BrowserLike,
  type ChromiumLauncher,
  type PageLike,
} from "../src/x2-render.js";

function fakePage(opts: {
  status?: number;
  finalUrl: string;
  html: string;
  noResponse?: boolean;
}): PageLike & { headersSeen: Record<string, string> | null; closed: boolean } {
  const page = {
    headersSeen: null as Record<string, string> | null,
    closed: false,
    async setExtraHTTPHeaders(headers: Record<string, string>) {
      page.headersSeen = headers;
    },
    async goto() {
      if (opts.noResponse) return null;
      return {
        status: () => opts.status ?? 200,
        url: () => opts.finalUrl,
      };
    },
    async content() {
      return opts.html;
    },
    async close() {
      page.closed = true;
    },
  };
  return page;
}

function fakeLauncher(page: PageLike): {
  launch: ChromiumLauncher;
  seenExecutablePath: string[];
  seenArgs: (string[] | undefined)[];
  closed: boolean;
} {
  const state = {
    launch: (() => {}) as unknown as ChromiumLauncher,
    seenExecutablePath: [] as string[],
    seenArgs: [] as (string[] | undefined)[],
    closed: false,
  };
  const browser: BrowserLike = {
    async newPage() {
      return page;
    },
    async close() {
      state.closed = true;
    },
  };
  state.launch = (async (opts: {
    executablePath: string;
    headless: boolean;
    args?: string[];
  }) => {
    state.seenExecutablePath.push(opts.executablePath);
    state.seenArgs.push(opts.args);
    expect(opts.headless).toBe(true);
    return browser;
  }) as ChromiumLauncher;
  return state;
}

describe("x2-render: renderUrl (decision 0001 Addendum J(a)(i))", () => {
  it("launches Chromium at the default pinned executablePath, sets the User-Agent, and returns status/finalUrl/html", async () => {
    const page = fakePage({
      status: 200,
      finalUrl: "https://golfvancouverisland.ca/",
      html: "<html><body><h1>Vancouver Island Golf Trail</h1></body></html>",
    });
    const { launch, seenExecutablePath } = fakeLauncher(page);
    const result = await renderUrl("https://golfvancouverisland.ca/", {
      userAgent: "GolfRaven-P0-X2/0.1 (test)",
      launch,
    });
    expect(result.status).toBe(200);
    expect(result.finalUrl).toBe("https://golfvancouverisland.ca/");
    expect(result.html).toContain("Vancouver Island Golf Trail");
    expect(seenExecutablePath).toEqual([DEFAULT_CHROMIUM_EXECUTABLE_PATH]);
    expect(page.headersSeen).toEqual({
      "User-Agent": "GolfRaven-P0-X2/0.1 (test)",
    });
    expect(page.closed).toBe(true);
  });

  it("passes extraArgs through to the launcher unchanged (e.g. an environment-specific TLS-trust escape hatch), and omits `args` when none given", async () => {
    const page = fakePage({
      finalUrl: "https://example.test/",
      html: "<p>x</p>",
    });
    const { launch, seenArgs } = fakeLauncher(page);
    await renderUrl("https://example.test/", { userAgent: "ua", launch });
    expect(seenArgs).toEqual([undefined]);

    await renderUrl("https://example.test/", {
      userAgent: "ua",
      launch,
      extraArgs: ["--ignore-certificate-errors-spki-list=abc123"],
    });
    expect(seenArgs[1]).toEqual([
      "--ignore-certificate-errors-spki-list=abc123",
    ]);
  });

  it("uses an explicit executablePath when given, instead of the default", async () => {
    const page = fakePage({
      finalUrl: "https://example.test/",
      html: "<p>x</p>",
    });
    const { launch, seenExecutablePath } = fakeLauncher(page);
    await renderUrl("https://example.test/", {
      userAgent: "ua",
      launch,
      executablePath: "/custom/chromium",
    });
    expect(seenExecutablePath).toEqual(["/custom/chromium"]);
  });

  it("gate N6: refuses (throws) a non-https URL before ever launching a browser", async () => {
    const page = fakePage({ finalUrl: "x", html: "x" });
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
    const page = fakePage({ finalUrl: "x", html: "x" });
    const { launch } = fakeLauncher(page);
    const launchSpy = vi.fn(launch);
    await expect(
      renderUrl("not a url", { userAgent: "ua", launch: launchSpy }),
    ).rejects.toThrow(/not a valid URL/);
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("throws, and still closes the browser, when navigation produces no response at all", async () => {
    const page = fakePage({
      finalUrl: "https://x.test/",
      html: "",
      noResponse: true,
    });
    const { launch, closed } = fakeLauncher(page);
    await expect(
      renderUrl("https://x.test/", { userAgent: "ua", launch }),
    ).rejects.toThrow(/produced no response/);
  });

  it("closes the page and the browser even when goto throws", async () => {
    let pageClosed = false;
    let browserClosed = false;
    const page: PageLike = {
      async setExtraHTTPHeaders() {},
      async goto() {
        throw new Error("navigation failed");
      },
      async content() {
        return "";
      },
      async close() {
        pageClosed = true;
      },
    };
    const browser: BrowserLike = {
      async newPage() {
        return page;
      },
      async close() {
        browserClosed = true;
      },
    };
    const launch: ChromiumLauncher = async () => browser;
    await expect(
      renderUrl("https://x.test/", { userAgent: "ua", launch }),
    ).rejects.toThrow(/navigation failed/);
    expect(pageClosed).toBe(true);
    expect(browserClosed).toBe(true);
  });
});
