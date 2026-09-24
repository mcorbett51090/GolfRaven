import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { runX2Fetch, type X2FetchManifest, type X2SourceConfig } from "../src/x2-fetch.js";
import {
  ingestOwnerSavedPage,
  statedHostAllowed,
  trailConfiguredHosts,
} from "../src/x2-ingest.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-x2-ingest-test-"));

afterEach(() => {
  vi.unstubAllGlobals();
});

const TN_CONFIG: X2SourceConfig = {
  TN: ["https://www.tnstateparks.com/golf", "https://tngolftrail.net/"],
  VI: ["https://golfvancouverisland.ca/"],
};

function writeFixtureHtml(name: string, html: string): string {
  const p = path.join(OUT_DIR, name);
  writeFileSync(p, html, "utf8");
  return p;
}

describe("x2-ingest: trailConfiguredHosts / statedHostAllowed (decision 0001 Addendum J(a) host allow-list)", () => {
  it("extracts hosts from a trail's configured URLs", () => {
    expect(trailConfiguredHosts(TN_CONFIG.TN!)).toEqual([
      "www.tnstateparks.com",
      "tngolftrail.net",
    ]);
  });

  it("allows a stated URL whose host exactly matches a configured host", () => {
    expect(statedHostAllowed("https://tngolftrail.net/rules", trailConfiguredHosts(TN_CONFIG.TN!))).toBe(
      true,
    );
  });

  it("allows a stated URL whose host differs only by a leading www.", () => {
    expect(
      statedHostAllowed("https://tnstateparks.com/golf", trailConfiguredHosts(TN_CONFIG.TN!)),
    ).toBe(true);
  });

  it("refuses a stated URL on a host the trail never configured", () => {
    expect(
      statedHostAllowed("https://evil.example/tnstateparks.com", trailConfiguredHosts(TN_CONFIG.TN!)),
    ).toBe(false);
  });
});

describe("x2-ingest: ingestOwnerSavedPage", () => {
  it("stores an owner-saved HTML file as evidence with method 'owner-saved', the stated URL and date", async () => {
    const html =
      "<html><body><h1>Tennessee Golf Trail</h1><p>Nine courses make up the Trail. Season runs year-round.</p></body></html>";
    const file = writeFixtureHtml("tn-owner-saved.html", html);
    const outDir = path.join(OUT_DIR, "ingest-run-1");
    const { entry, manifest } = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
    });

    expect(entry.status).toBe("fetched");
    expect(entry.method).toBe("owner-saved");
    expect(entry.httpStatus).toBe("owner-saved");
    expect(entry.url).toBe("https://www.tnstateparks.com/golf");
    expect(entry.ownerSavedDate).toBe("2026-09-24");
    expect(entry.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.fetchedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    const rawBytes = readFileSync(path.join(outDir, entry.rawFile!), "utf8");
    expect(rawBytes).toBe(html);
    const text = readFileSync(path.join(outDir, entry.textFile!), "utf8");
    expect(text).toContain("Tennessee Golf Trail");
    expect(text).toContain("Season runs year-round.");

    expect(manifest.trails.TN).toHaveLength(1);
    const onDisk = JSON.parse(readFileSync(path.join(outDir, "manifest.json"), "utf8")) as X2FetchManifest;
    expect(onDisk.trails.TN?.[0]?.method).toBe("owner-saved");
  });

  it("merges into an EXISTING x2-fetch evidence dir's manifest rather than overwriting it", async () => {
    const outDir = path.join(OUT_DIR, "merge-run");
    // A prior x2-fetch run already populated this evidence dir.
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("<h1>Existing direct-fetch entry</h1>", {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );
    await runX2Fetch({ TN: ["https://www.tnstateparks.com/golf"] }, outDir);
    vi.unstubAllGlobals();

    const file = writeFixtureHtml("tn-owner-saved-2.html", "<h1>Owner saved copy</h1>");
    const { manifest } = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file,
      statedUrl: "https://tngolftrail.net/rules",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
    });

    expect(manifest.trails.TN).toHaveLength(2);
    expect(manifest.trails.TN?.[0]?.method).toBe("direct");
    expect(manifest.trails.TN?.[1]?.method).toBe("owner-saved");
  });

  it("gate N6: refuses a non-https stated URL", async () => {
    const file = writeFixtureHtml("tn-http.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "http://www.tnstateparks.com/golf",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "http-run"),
      }),
    ).rejects.toThrow(/gate N6/);
  });

  it("decision 0001 Addendum J(a): refuses a stated URL whose host is not on the trail's configured host list", async () => {
    const file = writeFixtureHtml("tn-foreign.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "https://tn.gov/",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "foreign-host-run"),
      }),
    ).rejects.toThrow(/configured host list/);
  });

  it("refuses a malformed stated date", async () => {
    const file = writeFixtureHtml("tn-baddate.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "09/24/2026",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "baddate-run"),
      }),
    ).rejects.toThrow(/not a real YYYY-MM-DD/);
  });

  it("refuses a syntactically YYYY-MM-DD but non-existent calendar date", async () => {
    const file = writeFixtureHtml("tn-badcal.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "2026-02-30",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "badcal-run"),
      }),
    ).rejects.toThrow(/not a real calendar date/);
  });

  it("refuses a trail with no entry in the source config", async () => {
    const file = writeFixtureHtml("ok-trail.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "OK",
        filePath: file,
        statedUrl: "https://oklahomagolftrail.example/",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "unknown-trail-run"),
      }),
    ).rejects.toThrow(/no entry in the source config/);
  });

  it("refuses a missing file", async () => {
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: path.join(OUT_DIR, "does-not-exist.html"),
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "missing-file-run"),
      }),
    ).rejects.toThrow(/could not read --file/);
  });
});
