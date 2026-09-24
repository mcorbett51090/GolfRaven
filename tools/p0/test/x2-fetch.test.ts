import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  renderManifestSummary,
  resolveDefaultX2ConfigPath,
  runX2Fetch,
  type X2SourceConfig,
} from "../src/x2-fetch.js";
import type {
  BrowserLike,
  ChromiumLauncher,
  PageLike,
} from "../src/x2-render.js";
import { buildMinimalPdf } from "./fixtures/pdf/build-mini-pdf.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-x2-test-"));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("x2-fetch: resolveDefaultX2ConfigPath", () => {
  it("resolves to config/x2-sources.json under the package root, and that file exists", () => {
    const p = resolveDefaultX2ConfigPath();
    expect(p.endsWith(path.join("config", "x2-sources.json"))).toBe(true);
    expect(existsSync(p)).toBe(true);
  });
});

describe("x2-fetch: runX2Fetch — HTML evidence storage (decision 0001 Addendum G)", () => {
  it("stores raw bytes, final URL, HTTP status, fetchedAt, SHA-256 and extracted text for a successful HTML fetch", async () => {
    const html =
      "<html><body><h1>Tennessee Golf Trail</h1>" +
      "<p>Nine   courses make up the Trail.</p></body></html>";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const res = new Response(html, {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
        });
        Object.defineProperty(res, "url", {
          value: "https://www.tnstateparks.com/golf/",
        });
        return res;
      }),
    );

    const config: X2SourceConfig = {
      TN: ["https://www.tnstateparks.com/golf"],
    };
    const outDir = path.join(OUT_DIR, "html-run");
    const manifest = await runX2Fetch(config, outDir);

    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("fetched");
    expect(entry?.httpStatus).toBe(200);
    expect(entry?.finalUrl).toBe("https://www.tnstateparks.com/golf/");
    expect(entry?.fetchedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(entry?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(entry?.textExtraction).toBe("auto");
    expect(entry?.rawFile).toBeTruthy();
    expect(entry?.textFile).toBeTruthy();

    const rawBytes = readFileSync(path.join(outDir, entry!.rawFile!), "utf8");
    expect(rawBytes).toBe(html);
    const text = readFileSync(path.join(outDir, entry!.textFile!), "utf8");
    expect(text.trim()).toBe(
      "Tennessee Golf Trail Nine courses make up the Trail.",
    );

    expect(manifest.draftCandidateNames.TN).toContain("Tennessee Golf Trail");

    const manifestOnDisk = JSON.parse(
      readFileSync(path.join(outDir, "manifest.json"), "utf8"),
    );
    expect(manifestOnDisk.trails.TN[0].sha256).toBe(entry?.sha256);
  });

  it("gate S3: stores a REAL PDF's bytes and auto-extracts its text with the pinned extractor — never 'manual'", async () => {
    const quote =
      "The Trail Pass unit is the facility. Season runs year-round.";
    const pdfBytes = buildMinimalPdf(quote);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const res = new Response(pdfBytes, {
          status: 200,
          headers: { "content-type": "application/pdf" },
        });
        Object.defineProperty(res, "url", {
          value:
            "https://golfvancouverisland.ca/wp-content/uploads/2024/10/2024-GVI-Trail-Pass-Terms-and-Restrictions.pdf",
        });
        return res;
      }),
    );

    const config: X2SourceConfig = {
      VI: [
        "https://golfvancouverisland.ca/wp-content/uploads/2024/10/2024-GVI-Trail-Pass-Terms-and-Restrictions.pdf",
      ],
    };
    const outDir = path.join(OUT_DIR, "pdf-run");
    const manifest = await runX2Fetch(config, outDir);

    const entry = manifest.trails.VI?.[0];
    expect(entry?.status).toBe("fetched");
    expect(entry?.textExtraction).toBe("auto-pdf");
    expect(entry?.extractor).toBe("unpdf@1.8.1");
    expect(entry?.textFile).toBeTruthy();
    expect(entry?.rawFile?.endsWith(".pdf")).toBe(true);

    const raw = readFileSync(path.join(outDir, entry!.rawFile!));
    expect(raw.equals(pdfBytes)).toBe(true);
    const text = readFileSync(path.join(outDir, entry!.textFile!), "utf8");
    expect(text).toContain(quote);
  });

  it("gate N5: a .pdf URL that actually serves an HTML error page is stored as binary, not mis-read as PDF text or HTML", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("<html>404 Not Found</html>", {
            status: 200,
            headers: { "content-type": "application/pdf" },
          }),
      ),
    );
    const config: X2SourceConfig = {
      VI: ["https://golfvancouverisland.ca/missing.pdf"],
    };
    const outDir = path.join(OUT_DIR, "fake-pdf-run");
    const manifest = await runX2Fetch(config, outDir);
    const entry = manifest.trails.VI?.[0];
    expect(entry?.status).toBe("fetched");
    expect(entry?.textExtraction).toBe("n/a");
    expect(entry?.textFile).toBeNull();
    expect(entry?.rawFile?.endsWith(".bin")).toBe(true);
  });

  it("records a network-policy-blocked fetch as FAILED with the exact error, never silently skipped", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("CONNECT tunnel failed, response 403");
      }),
    );

    const config: X2SourceConfig = { RTJ: ["https://www.rtjgolf.com/"] };
    const outDir = path.join(OUT_DIR, "blocked-run");
    const manifest = await runX2Fetch(config, outDir);

    const entry = manifest.trails.RTJ?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.blocked).toBe(true);
    expect(entry?.error).toContain("BLOCKED — network policy");
    expect(entry?.error).toContain("www.rtjgolf.com");
    expect(entry?.sha256).toBeNull();
    expect(entry?.rawFile).toBeNull();
  });

  it("records a non-blocked HTTP failure (e.g. 404) as FAILED too, distinct from a network-policy block", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("not found", { status: 404, statusText: "Not Found" }),
      ),
    );
    const config: X2SourceConfig = { TN: ["https://tngolftrail.net/missing"] };
    const outDir = path.join(OUT_DIR, "404-run");
    const manifest = await runX2Fetch(config, outDir);
    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.blocked).toBe(false);
    expect(entry?.error).toContain("404");
  });

  it("gate N6: refuses a non-https configured URL rather than fetching it", async () => {
    const fetchSpy = vi.fn(async () => new Response("should never be called"));
    vi.stubGlobal("fetch", fetchSpy);
    const config: X2SourceConfig = { TN: ["http://www.tnstateparks.com/golf"] };
    const outDir = path.join(OUT_DIR, "http-scheme-run");
    const manifest = await runX2Fetch(config, outDir);
    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.error).toContain("gate N6");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gate N6: refuses a data: URL rather than fetching it", async () => {
    const fetchSpy = vi.fn(async () => new Response("should never be called"));
    vi.stubGlobal("fetch", fetchSpy);
    const config: X2SourceConfig = { TN: ["data:text/html,<h1>hi</h1>"] };
    const outDir = path.join(OUT_DIR, "data-url-run");
    const manifest = await runX2Fetch(config, outDir);
    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.error).toContain("gate N6");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gate S6: a body that streams past the size cap is recorded as failed, not silently truncated into evidence", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array(11 * 1024 * 1024));
            controller.close();
          },
        });
        const res = new Response(stream, {
          status: 200,
          headers: { "content-type": "text/html" },
        });
        Object.defineProperty(res, "url", {
          value: "https://www.tnstateparks.com/golf",
        });
        return res;
      }),
    );
    const config: X2SourceConfig = {
      TN: ["https://www.tnstateparks.com/golf"],
    };
    const outDir = path.join(OUT_DIR, "oversized-run");
    const manifest = await runX2Fetch(config, outDir);
    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.error).toContain("size cap");
  });

  it("continues fetching remaining URLs after one fails, and refuses on an empty config", async () => {
    let call = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        call += 1;
        if (call === 1) throw new Error("CONNECT tunnel failed, response 403");
        return new Response("<h1>OK Page</h1>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }),
    );
    const config: X2SourceConfig = {
      TN: ["https://www.tnstateparks.com/golf", "https://tn.gov/"],
    };
    const outDir = path.join(OUT_DIR, "mixed-run");
    const manifest = await runX2Fetch(config, outDir);
    expect(manifest.trails.TN?.map((e) => e.status)).toEqual([
      "failed",
      "fetched",
    ]);

    await expect(
      runX2Fetch({}, path.join(OUT_DIR, "empty-run")),
    ).rejects.toThrow(/empty source list/);
  });
});

function fakeRenderLauncher(opts: {
  status?: number;
  finalUrl: string;
  html: string;
}): { launch: ChromiumLauncher; userAgentSeen: string | null } {
  const state = { userAgentSeen: null as string | null };
  const page: PageLike = {
    async setExtraHTTPHeaders(headers) {
      state.userAgentSeen = headers["User-Agent"] ?? null;
    },
    async goto() {
      return { status: () => opts.status ?? 200, url: () => opts.finalUrl };
    },
    async content() {
      return opts.html;
    },
    async close() {},
  };
  const browser: BrowserLike = {
    async newPage() {
      return page;
    },
    async close() {},
  };
  const launch: ChromiumLauncher = async () => browser;
  return { launch, userAgentSeen: state.userAgentSeen };
}

describe("x2-fetch: runX2Fetch --render mode (decision 0001 Addendum J(a)(i))", () => {
  it("stores the rendered page.content() bytes and extracted text, with method 'rendered', via an injected launcher (no real browser)", async () => {
    const html =
      '<html><body><div id="app">' +
      "<h1>Vancouver Island Golf Trail</h1><p>Rendered after JS ran.</p></div></body></html>";
    const { launch } = fakeRenderLauncher({
      finalUrl: "https://golfvancouverisland.ca/",
      html,
    });
    const config: X2SourceConfig = { VI: ["https://golfvancouverisland.ca/"] };
    const outDir = path.join(OUT_DIR, "render-run");
    const manifest = await runX2Fetch(config, outDir, {
      render: true,
      renderLaunch: launch,
    });

    const entry = manifest.trails.VI?.[0];
    expect(entry?.status).toBe("fetched");
    expect(entry?.method).toBe("rendered");
    expect(entry?.httpStatus).toBe(200);
    expect(entry?.finalUrl).toBe("https://golfvancouverisland.ca/");
    expect(entry?.sha256).toMatch(/^[0-9a-f]{64}$/);

    const rawBytes = readFileSync(path.join(outDir, entry!.rawFile!), "utf8");
    expect(rawBytes).toBe(html);
    const text = readFileSync(path.join(outDir, entry!.textFile!), "utf8");
    expect(text).toContain("Vancouver Island Golf Trail");
    expect(text).toContain("Rendered after JS ran.");
  });

  it("keeps the tool's own bot-identifying User-Agent when rendering, never a browser UA", async () => {
    const state = { userAgentSeen: null as string | null };
    const page: PageLike = {
      async setExtraHTTPHeaders(headers) {
        state.userAgentSeen = headers["User-Agent"] ?? null;
      },
      async goto() {
        return {
          status: () => 200,
          url: () => "https://golfvancouverisland.ca/",
        };
      },
      async content() {
        return "<p>x</p>";
      },
      async close() {},
    };
    const browser: BrowserLike = {
      async newPage() {
        return page;
      },
      async close() {},
    };
    const launch: ChromiumLauncher = async () => browser;
    const config: X2SourceConfig = { VI: ["https://golfvancouverisland.ca/"] };
    await runX2Fetch(config, path.join(OUT_DIR, "render-ua-run"), {
      render: true,
      renderLaunch: launch,
    });
    expect(state.userAgentSeen).toMatch(/^GolfRaven-P0-X2\/0\.1/);
    expect(state.userAgentSeen).not.toMatch(/Mozilla|Chrome|Safari/);
  });

  it("gate N6: refuses to render a non-https configured URL, never launching a browser", async () => {
    const launchSpy = vi.fn<ChromiumLauncher>();
    const config: X2SourceConfig = { TN: ["http://www.tnstateparks.com/golf"] };
    const manifest = await runX2Fetch(
      config,
      path.join(OUT_DIR, "render-http-run"),
      {
        render: true,
        renderLaunch: launchSpy,
      },
    );
    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.error).toContain("gate N6");
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("records a render failure (e.g. navigation error) as FAILED with method 'rendered', never silently skipped", async () => {
    const browser: BrowserLike = {
      async newPage() {
        return {
          async setExtraHTTPHeaders() {},
          async goto() {
            throw new Error("net::ERR_CONNECTION_REFUSED");
          },
          async content() {
            return "";
          },
          async close() {},
        };
      },
      async close() {},
    };
    const launch: ChromiumLauncher = async () => browser;
    const config: X2SourceConfig = { VI: ["https://golfvancouverisland.ca/"] };
    const manifest = await runX2Fetch(
      config,
      path.join(OUT_DIR, "render-fail-run"),
      {
        render: true,
        renderLaunch: launch,
      },
    );
    const entry = manifest.trails.VI?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.method).toBe("rendered");
    expect(entry?.error).toContain("ERR_CONNECTION_REFUSED");
  });

  it("a direct (non-render) run still stamps method 'direct' on every entry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("<h1>Tennessee Golf Trail</h1>", {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );
    const config: X2SourceConfig = {
      TN: ["https://www.tnstateparks.com/golf"],
    };
    const manifest = await runX2Fetch(
      config,
      path.join(OUT_DIR, "direct-method-run"),
    );
    expect(manifest.trails.TN?.[0]?.method).toBe("direct");
  });
});

describe("x2-fetch: renderManifestSummary", () => {
  it("labels the candidate list DRAFT and never as a confirmation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("<h1>Some Trail</h1>", {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );
    const manifest = await runX2Fetch(
      { TN: ["https://www.tnstateparks.com/golf"] },
      path.join(OUT_DIR, "summary-run"),
    );
    const summary = renderManifestSummary(manifest);
    expect(summary).toContain("DRAFT candidate names");
    expect(summary).toContain("NOT a confirmation");
  });
});
