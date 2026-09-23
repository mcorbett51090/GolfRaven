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

    const config: X2SourceConfig = { TN: ["https://www.tnstateparks.com/golf"] };
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

  it("stores a PDF's bytes but marks text extraction 'manual' — never pretends to have read it", async () => {
    const pdfBytes = Buffer.from("%PDF-1.4 fake pdf bytes for a test");
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
    expect(entry?.textExtraction).toBe("manual");
    expect(entry?.textFile).toBeNull();
    expect(entry?.rawFile?.endsWith(".pdf")).toBe(true);
    expect(entry?.draftCandidateNames).toEqual([]);

    const raw = readFileSync(path.join(outDir, entry!.rawFile!));
    expect(raw.equals(pdfBytes)).toBe(true);
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
      vi.fn(async () => new Response("not found", { status: 404, statusText: "Not Found" })),
    );
    const config: X2SourceConfig = { TN: ["https://tngolftrail.net/missing"] };
    const outDir = path.join(OUT_DIR, "404-run");
    const manifest = await runX2Fetch(config, outDir);
    const entry = manifest.trails.TN?.[0];
    expect(entry?.status).toBe("failed");
    expect(entry?.blocked).toBe(false);
    expect(entry?.error).toContain("404");
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

    await expect(runX2Fetch({}, path.join(OUT_DIR, "empty-run"))).rejects.toThrow(
      /empty source list/,
    );
  });
});

describe("x2-fetch: renderManifestSummary", () => {
  it("labels the candidate list DRAFT and never as a confirmation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("<h1>Some Trail</h1>", {
        status: 200,
        headers: { "content-type": "text/html" },
      })),
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
