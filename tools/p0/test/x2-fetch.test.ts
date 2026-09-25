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
  ContextLike,
  PageLike,
} from "../src/x2-render.js";
import { buildMinimalPdf } from "./fixtures/pdf/build-mini-pdf.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-x2-test-"));

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Gate finding 2c (re-gate): the per-directory default ledger was removed
 * — `ledgerPath` is now a required option on `runX2Fetch`. Most tests in
 * this file don't care about cross-run ledger sharing at all; they just
 * need SOME explicit ledger scoped to their own `outDir`, reproducing what
 * the removed default used to compute automatically — this helper makes
 * that a one-line, deliberate choice at each call site instead of an
 * implicit fallback inside the tool itself. */
function ledgerFor(dir: string): string {
  return path.join(dir, "recorded-ledger.json");
}

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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });

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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });

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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });

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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
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
    const manifest = await runX2Fetch(config, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
    expect(manifest.trails.TN?.map((e) => e.status)).toEqual([
      "failed",
      "fetched",
    ]);

    await expect(
      runX2Fetch({}, path.join(OUT_DIR, "empty-run"), {
        ledgerPath: ledgerFor(path.join(OUT_DIR, "empty-run")),
      }),
    ).rejects.toThrow(/empty source list/);
  });
});

describe("x2-fetch: gate finding 2b — manifest MERGE, never overwrite", () => {
  function okHtmlFetch(bodyByUrl: Record<string, string>) {
    return vi.fn(async (input: string | URL) => {
      const url = String(input);
      const body = bodyByUrl[url] ?? "<h1>fallback</h1>";
      const res = new Response(body, {
        status: 200,
        headers: { "content-type": "text/html" },
      });
      Object.defineProperty(res, "url", { value: url });
      return res;
    });
  }

  it("a run for trail B does not drop trail A's entries already in manifest.json", async () => {
    const outDir = path.join(OUT_DIR, "merge-trails");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/tn": "<h1>TN page</h1>" }),
    );
    const manifestA = await runX2Fetch(
      { TN: ["https://example.com/tn"] },
      outDir,
      { ledgerPath: ledgerFor(outDir) },
    );
    expect(manifestA.trails.TN).toHaveLength(1);

    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/vi": "<h1>VI page</h1>" }),
    );
    const manifestB = await runX2Fetch(
      { VI: ["https://example.com/vi"] },
      outDir,
      { ledgerPath: ledgerFor(outDir) },
    );
    // Trail TN, from the FIRST run, must still be present.
    expect(manifestB.trails.TN).toHaveLength(1);
    expect(manifestB.trails.TN?.[0]?.status).toBe("fetched");
    expect(manifestB.trails.VI).toHaveLength(1);

    // And the manifest actually written to disk reflects both trails too
    // — not just the in-memory return value.
    const onDisk = JSON.parse(
      readFileSync(path.join(outDir, "manifest.json"), "utf8"),
    );
    expect(Object.keys(onDisk.trails).sort()).toEqual(["TN", "VI"]);
  });

  it("a second run for the SAME trail APPENDS new entries rather than replacing the old ones", async () => {
    const outDir = path.join(OUT_DIR, "merge-append-same-trail");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/tn-1": "<h1>TN page one</h1>" }),
    );
    const manifestA = await runX2Fetch(
      { TN: ["https://example.com/tn-1"] },
      outDir,
      { ledgerPath: ledgerFor(outDir) },
    );
    expect(manifestA.trails.TN).toHaveLength(1);

    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/tn-2": "<h1>TN page two</h1>" }),
    );
    const manifestB = await runX2Fetch(
      { TN: ["https://example.com/tn-2"] },
      outDir,
      { ledgerPath: ledgerFor(outDir) },
    );
    // Both the original and the new entry must be present — never replaced.
    expect(manifestB.trails.TN).toHaveLength(2);
    expect(manifestB.trails.TN?.map((e) => e.url)).toEqual([
      "https://example.com/tn-1",
      "https://example.com/tn-2",
    ]);
  });

  it("generatedAt is preserved from the FIRST run, not overwritten by a later merge", async () => {
    const outDir = path.join(OUT_DIR, "merge-generatedAt");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/tn": "<h1>TN</h1>" }),
    );
    const manifestA = await runX2Fetch({ TN: ["https://example.com/tn"] }, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
    const firstGeneratedAt = manifestA.generatedAt;

    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/vi": "<h1>VI</h1>" }),
    );
    const manifestB = await runX2Fetch({ VI: ["https://example.com/vi"] }, outDir, {
      ledgerPath: ledgerFor(outDir),
    });
    expect(manifestB.generatedAt).toBe(firstGeneratedAt);
  });
});

describe("x2-fetch: gate finding 2c — the recorded-captures ledger (first-capture-wins is NOT hard-coded)", () => {
  function okHtmlFetch(bodyByUrl: Record<string, string>) {
    return vi.fn(async (input: string | URL) => {
      const url = String(input);
      const body = bodyByUrl[url] ?? "<h1>fallback</h1>";
      const res = new Response(body, {
        status: 200,
        headers: { "content-type": "text/html" },
      });
      Object.defineProperty(res, "url", { value: url });
      return res;
    });
  }

  it("the first capture of a URL is recorded: true", async () => {
    const outDir = path.join(OUT_DIR, "ledger-first");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/trail": "<h1>Trail page</h1>" }),
    );
    const manifest = await runX2Fetch(
      { TN: ["https://example.com/trail"] },
      outDir,
      { ledgerPath: ledgerFor(outDir) },
    );
    expect(manifest.trails.TN?.[0]?.recorded).toBe(true);
  });

  it("a later capture of a NORMALIZED-EQUAL URL (different run, same out-dir/ledger) comes back recorded: false — first-capture-wins actually enforced, not hard-coded", async () => {
    const outDir = path.join(OUT_DIR, "ledger-duplicate");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/trail": "<h1>Trail page v1</h1>" }),
    );
    const manifestA = await runX2Fetch(
      { TN: ["https://example.com/trail"] },
      outDir,
      { ledgerPath: ledgerFor(outDir) },
    );
    expect(manifestA.trails.TN?.[0]?.recorded).toBe(true);

    // A second run, same out-dir (same EXPLICIT ledger — gate finding 2c
    // re-gate: no more automatic per-directory default), for a
    // *bypass-shaped* variant of the exact same URL (www. + trailing
    // slash) — must NOT silently look like a fresh first capture.
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({
        "https://www.example.com/trail/": "<h1>Trail page v2 (a later capture)</h1>",
      }),
    );
    const manifestB = await runX2Fetch(
      { TN: ["https://www.example.com/trail/"] },
      outDir,
      { ledgerPath: ledgerFor(outDir) },
    );
    const secondEntry = manifestB.trails.TN?.[1];
    expect(secondEntry?.status).toBe("fetched"); // stored as real evidence...
    expect(secondEntry?.recorded).toBe(false); // ...but never the recorded one.
  });

  it("a shared --ledger path across two different out-dirs is what makes cross-run duplicate detection possible at all — without it, two separate out-dirs would each see a 'first' capture", async () => {
    const ledgerPath = path.join(OUT_DIR, "shared-ledger", "recorded-ledger.json");
    const outDirA = path.join(OUT_DIR, "ledger-shared-a");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/shared-trail": "<h1>Shared trail</h1>" }),
    );
    const manifestA = await runX2Fetch(
      { TN: ["https://example.com/shared-trail"] },
      outDirA,
      { ledgerPath },
    );
    expect(manifestA.trails.TN?.[0]?.recorded).toBe(true);

    const outDirB = path.join(OUT_DIR, "ledger-shared-b");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/shared-trail": "<h1>Shared trail, again</h1>" }),
    );
    const manifestB = await runX2Fetch(
      { TN: ["https://example.com/shared-trail"] },
      outDirB,
      { ledgerPath },
    );
    // Direct/render re-captures (unlike owner-saved --additional) are never
    // hard-refused — a legitimate re-verification fetch must still work —
    // but the SECOND out-dir's capture must come back recorded: false,
    // because it shares run A's ledger and can see run A's entry.
    expect(manifestB.trails.TN?.[0]?.recorded).toBe(false);

    // Without a SHARED ledger (i.e. each out-dir given its OWN separate,
    // still-explicit ledger — gate finding 2c re-gate removed the implicit
    // per-directory default entirely, so this is now `ledgerFor(outDirC)`,
    // not an omitted argument), the same scenario would wrongly mark BOTH
    // as recorded: true — that is exactly the bug gate finding 2c called
    // out. Prove the negative case too, so this test would fail if
    // `ledgerPath` sharing were ever silently dropped.
    const outDirC = path.join(OUT_DIR, "ledger-unshared-c");
    vi.stubGlobal(
      "fetch",
      okHtmlFetch({ "https://example.com/unshared-trail": "<h1>Unshared</h1>" }),
    );
    const manifestC = await runX2Fetch(
      { TN: ["https://example.com/unshared-trail"] },
      outDirC,
      { ledgerPath: ledgerFor(outDirC) }, // its OWN ledger, not the shared one above
    );
    expect(manifestC.trails.TN?.[0]?.recorded).toBe(true);
  });
});

/** A minimal PageLike that passes every request through unmodified — for
 * tests in THIS file that exercise `runX2Fetch`'s render plumbing, not
 * `x2-render.ts`'s own off-host/https/byte-cap/isolation logic (that logic
 * has its own dedicated, thorough coverage in `x2-render.test.ts`). */
function passthroughPage(opts: { status?: number; finalUrl: string; html: string }): PageLike {
  return {
    url() {
      return opts.finalUrl;
    },
    mainFrame() {
      return {};
    },
    async goto() {
      return { status: () => opts.status ?? 200, url: () => opts.finalUrl, headers: () => ({}) };
    },
    async content() {
      return opts.html;
    },
    async close() {},
    on() {},
  };
}

/** A minimal ContextLike matching the passthrough page above — routing/
 * websocket/popup handlers are all no-ops, since this file exercises
 * `runX2Fetch`'s plumbing, not `x2-render.ts`'s own isolation logic. */
function passthroughContext(page: PageLike): ContextLike {
  return {
    async newPage() {
      return page;
    },
    async route() {},
    async routeWebSocket() {},
    on() {},
    async addInitScript() {},
    async close() {},
  };
}

/** A no-op CDPSessionLike — for tests in THIS file that exercise
 * `runX2Fetch`'s render plumbing, not `x2-render.ts`'s own gate-finding-1
 * CDP-level worker watch (that has its own dedicated coverage in
 * `x2-render.test.ts`). */
function passthroughCDPSession() {
  return {
    on() {},
    async send() {
      return {};
    },
    async detach() {},
  };
}

function fakeRenderLauncher(opts: {
  status?: number;
  finalUrl: string;
  html: string;
}): { launch: ChromiumLauncher } {
  const page = passthroughPage(opts);
  const context = passthroughContext(page);
  const browser: BrowserLike = {
    async newContext() {
      return context;
    },
    async newBrowserCDPSession() {
      return passthroughCDPSession();
    },
    async close() {},
  };
  const launch: ChromiumLauncher = async () => browser;
  return { launch };
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
      ledgerPath: ledgerFor(outDir),
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

  it("keeps the tool's own bot-identifying User-Agent when rendering (via context.newContext, never a browser UA), and blocks Service Workers for the context", async () => {
    const state = { userAgentSeen: null as string | null, serviceWorkersSeen: null as string | null };
    const page = passthroughPage({ finalUrl: "https://golfvancouverisland.ca/", html: "<p>x</p>" });
    const context = passthroughContext(page);
    const browser: BrowserLike = {
      async newContext(contextOpts) {
        state.userAgentSeen = contextOpts.userAgent;
        state.serviceWorkersSeen = contextOpts.serviceWorkers ?? null;
        return context;
      },
      async newBrowserCDPSession() {
        return passthroughCDPSession();
      },
      async close() {},
    };
    const launch: ChromiumLauncher = async () => browser;
    const config: X2SourceConfig = { VI: ["https://golfvancouverisland.ca/"] };
    await runX2Fetch(config, path.join(OUT_DIR, "render-ua-run"), {
      render: true,
      renderLaunch: launch,
      ledgerPath: ledgerFor(path.join(OUT_DIR, "render-ua-run")),
    });
    expect(state.userAgentSeen).toMatch(/^GolfRaven-P0-X2\/0\.1/);
    expect(state.userAgentSeen).not.toMatch(/Mozilla|Chrome|Safari/);
    expect(state.serviceWorkersSeen).toBe("block");
  });

  it("should-fix: records the HTTPS_PROXY host (never credentials) in the manifest entry alongside renderArgs, for a rendered capture", async () => {
    vi.stubEnv("HTTPS_PROXY", "http://local_proxy:secret-token@127.0.0.1:41831");
    const html = "<html><body><h1>Vancouver Island Golf Trail</h1></body></html>";
    const { launch } = fakeRenderLauncher({
      finalUrl: "https://golfvancouverisland.ca/",
      html,
    });
    const config: X2SourceConfig = { VI: ["https://golfvancouverisland.ca/"] };
    const manifest = await runX2Fetch(config, path.join(OUT_DIR, "render-proxy-run"), {
      render: true,
      renderLaunch: launch,
      ledgerPath: ledgerFor(path.join(OUT_DIR, "render-proxy-run")),
    });
    const entry = manifest.trails.VI?.[0];
    expect(entry?.renderProxyHost).toBe("127.0.0.1:41831");
    // Never the raw env var value — that would leak the embedded credential.
    const onDisk = readFileSync(
      path.join(OUT_DIR, "render-proxy-run", "manifest.json"),
      "utf8",
    );
    expect(onDisk).not.toContain("secret-token");
    expect(onDisk).not.toContain("local_proxy");
    vi.unstubAllEnvs();
  });

  it("should-fix: renderProxyHost is null when no HTTPS_PROXY/https_proxy env var is set", async () => {
    vi.stubEnv("HTTPS_PROXY", undefined);
    vi.stubEnv("https_proxy", undefined);
    const html = "<html><body><h1>No proxy in effect</h1></body></html>";
    const { launch } = fakeRenderLauncher({
      finalUrl: "https://golfvancouverisland.ca/",
      html,
    });
    const config: X2SourceConfig = { VI: ["https://golfvancouverisland.ca/"] };
    const manifest = await runX2Fetch(config, path.join(OUT_DIR, "render-no-proxy-run"), {
      render: true,
      renderLaunch: launch,
      ledgerPath: ledgerFor(path.join(OUT_DIR, "render-no-proxy-run")),
    });
    expect(manifest.trails.VI?.[0]?.renderProxyHost).toBeNull();
    vi.unstubAllEnvs();
  });

  it("should-fix: a DIRECT (non-render) entry always has renderProxyHost: null, even with HTTPS_PROXY set", async () => {
    vi.stubEnv("HTTPS_PROXY", "http://127.0.0.1:9999");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const res = new Response("<h1>OK</h1>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
        Object.defineProperty(res, "url", { value: "https://example.com/tn" });
        return res;
      }),
    );
    const manifest = await runX2Fetch(
      { TN: ["https://example.com/tn"] },
      path.join(OUT_DIR, "direct-proxy-noop-run"),
      { ledgerPath: ledgerFor(path.join(OUT_DIR, "direct-proxy-noop-run")) },
    );
    expect(manifest.trails.TN?.[0]?.renderProxyHost).toBeNull();
    vi.unstubAllEnvs();
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
        ledgerPath: ledgerFor(path.join(OUT_DIR, "render-http-run")),
      },
    );
    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.error).toContain("gate N6");
    expect(launchSpy).not.toHaveBeenCalled();
  });

  it("records a render failure (e.g. navigation error) as FAILED with method 'rendered', never silently skipped", async () => {
    const page: PageLike = {
      mainFrame() {
        return {};
      },
      url() {
        return "";
      },
      async goto() {
        throw new Error("net::ERR_CONNECTION_REFUSED");
      },
      on() {},
      async content() {
        return "";
      },
      async close() {},
    };
    const context = passthroughContext(page);
    const browser: BrowserLike = {
      async newContext() {
        return context;
      },
      async newBrowserCDPSession() {
        return passthroughCDPSession();
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
        ledgerPath: ledgerFor(path.join(OUT_DIR, "render-fail-run")),
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
      { ledgerPath: ledgerFor(path.join(OUT_DIR, "direct-method-run")) },
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
      { ledgerPath: ledgerFor(path.join(OUT_DIR, "summary-run")) },
    );
    const summary = renderManifestSummary(manifest);
    expect(summary).toContain("DRAFT candidate names");
    expect(summary).toContain("NOT a confirmation");
  });
});
