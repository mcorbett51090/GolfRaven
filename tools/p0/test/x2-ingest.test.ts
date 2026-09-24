import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  runX2Fetch,
  type X2FetchManifest,
  type X2SourceConfig,
} from "../src/x2-fetch.js";
import {
  ingestOwnerSavedPage,
  statedHostAllowed,
  trailConfiguredHosts,
} from "../src/x2-ingest.js";

const OUT_DIR = mkdtempSync(
  path.join(tmpdir(), "golfraven-p0-x2-ingest-test-"),
);

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Gate finding 2c (re-gate): the per-directory default ledger was
 * removed — `ledgerPath` is now required on `ingestOwnerSavedPage`. Most
 * tests in this file don't care about cross-run ledger sharing; they just
 * need SOME explicit ledger scoped to their own `outDir` — reproducing
 * what the removed default used to compute automatically. */
function ledgerFor(dir: string): string {
  return path.join(dir, "recorded-ledger.json");
}

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
    expect(
      statedHostAllowed(
        "https://tngolftrail.net/rules",
        trailConfiguredHosts(TN_CONFIG.TN!),
      ),
    ).toBe(true);
  });

  it("allows a stated URL whose host differs only by a leading www.", () => {
    expect(
      statedHostAllowed(
        "https://tnstateparks.com/golf",
        trailConfiguredHosts(TN_CONFIG.TN!),
      ),
    ).toBe(true);
  });

  it("refuses a stated URL on a host the trail never configured", () => {
    expect(
      statedHostAllowed(
        "https://evil.example/tnstateparks.com",
        trailConfiguredHosts(TN_CONFIG.TN!),
      ),
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
      ledgerPath: ledgerFor(outDir),
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
    const onDisk = JSON.parse(
      readFileSync(path.join(outDir, "manifest.json"), "utf8"),
    ) as X2FetchManifest;
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

    const file = writeFixtureHtml(
      "tn-owner-saved-2.html",
      "<h1>Owner saved copy</h1>",
    );
    const { manifest } = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file,
      // Gate finding 2a (re-gate): must exactly match a configured URL,
      // not merely share an allowed host — TN_CONFIG's own root URL for
      // this host, not an arbitrary "/rules" path on it.
      statedUrl: "https://tngolftrail.net/",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
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
        ledgerPath: ledgerFor(path.join(OUT_DIR, "http-run")),
      }),
    ).rejects.toThrow(/gate N6/);
  });

  it("decision 0001 Addendum J(a) / gate finding 2a: refuses a stated URL whose host is not on the trail's configured host list", async () => {
    const file = writeFixtureHtml("tn-foreign.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "https://tn.gov/",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "foreign-host-run"),
        ledgerPath: ledgerFor(path.join(OUT_DIR, "foreign-host-run")),
      }),
    ).rejects.toThrow(/does not exactly match .* configured list/);
  });

  it("gate finding 2a (re-gate): refuses a stated URL on an ALLOWED host but a path the trail never configured (the host-only bypass this finding closed)", async () => {
    const file = writeFixtureHtml("tn-anypath.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        // "tnstateparks.com" (www-equivalent) IS an allowed HOST — but
        // "/anything-at-all" was never one of TN's configured URLs.
        statedUrl: "https://www.tnstateparks.com/anything-at-all",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "any-path-run"),
        ledgerPath: ledgerFor(path.join(OUT_DIR, "any-path-run")),
      }),
    ).rejects.toThrow(/does not exactly match .* configured list/);
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
        ledgerPath: ledgerFor(path.join(OUT_DIR, "baddate-run")),
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
        ledgerPath: ledgerFor(path.join(OUT_DIR, "badcal-run")),
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
        ledgerPath: ledgerFor(path.join(OUT_DIR, "unknown-trail-run")),
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
        ledgerPath: ledgerFor(path.join(OUT_DIR, "missing-file-run")),
      }),
    ).rejects.toThrow(/could not read --file/);
  });
});

describe("x2-ingest: gate findings — date bounds (Addendum J correction)", () => {
  it("refuses a date after the ingestion time (a future date)", async () => {
    const file = writeFixtureHtml("tn-future.html", "<h1>x</h1>");
    // "Today" in this test run is real wall-clock UTC — any date clearly
    // in the far future is unambiguous, so this doesn't depend on knowing
    // exactly what day the suite runs.
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "2099-12-31",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "future-date-run"),
        ledgerPath: ledgerFor(path.join(OUT_DIR, "future-date-run")),
      }),
    ).rejects.toThrow(/is after the latest possible "today" anywhere on Earth/);
  });

  it("should-fix: the future bound uses the LATEST timezone on Earth (UTC+14), not bare UTC — a date that is still 'today' in UTC+14 but already 'tomorrow' in UTC is accepted", async () => {
    const file = writeFixtureHtml("tn-utc14.html", "<h1>x</h1>");
    // "Tomorrow" in UTC is still "today" somewhere between UTC and
    // UTC+14 for up to 14 hours after UTC midnight — this stated date
    // must NOT be refused just because bare UTC has already rolled over.
    const nowUtcPlus14 = new Date(Date.now() + 14 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10);
    const { entry } = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: nowUtcPlus14,
      sourceConfig: TN_CONFIG,
      outDir: path.join(OUT_DIR, "utc14-boundary-run"),
      ledgerPath: ledgerFor(path.join(OUT_DIR, "utc14-boundary-run")),
    });
    expect(entry.ownerSavedDate).toBe(nowUtcPlus14);
  });

  it("should-fix: one day beyond the UTC+14 bound is still refused as a future date", async () => {
    const file = writeFixtureHtml("tn-utc14-over.html", "<h1>x</h1>");
    const oneDayBeyondUtc14 = new Date(
      Date.now() + 14 * 60 * 60 * 1000 + 24 * 60 * 60 * 1000,
    )
      .toISOString()
      .slice(0, 10);
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: oneDayBeyondUtc14,
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "utc14-over-run"),
        ledgerPath: ledgerFor(path.join(OUT_DIR, "utc14-over-run")),
      }),
    ).rejects.toThrow(/is after the latest possible "today" anywhere on Earth/);
  });

  it("refuses a date earlier than 2026-09-01", async () => {
    const file = writeFixtureHtml("tn-ancient.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "1999-01-01",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "ancient-date-run"),
        ledgerPath: ledgerFor(path.join(OUT_DIR, "ancient-date-run")),
      }),
    ).rejects.toThrow(/earlier than 2026-09-01/);
  });

  it("accepts 2026-09-01 itself (the boundary is inclusive)", async () => {
    const file = writeFixtureHtml("tn-boundary.html", "<h1>x</h1>");
    const { entry } = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-01",
      sourceConfig: TN_CONFIG,
      outDir: path.join(OUT_DIR, "boundary-date-run"),
      ledgerPath: ledgerFor(path.join(OUT_DIR, "boundary-date-run")),
    });
    expect(entry.ownerSavedDate).toBe("2026-09-01");
  });
});

describe("x2-ingest: gate findings — first-capture-wins (Addendum J correction)", () => {
  it("refuses a SECOND owner-saved capture of the same URL for the same trail without --additional", async () => {
    const outDir = path.join(OUT_DIR, "dup-run");
    const file1 = writeFixtureHtml("tn-dup-1.html", "<h1>First capture</h1>");
    await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file1,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
    });
    const file2 = writeFixtureHtml(
      "tn-dup-2.html",
      "<h1>Second capture, different bytes</h1>",
    );
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: file2,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir,
        ledgerPath: ledgerFor(outDir),
      }),
    ).rejects.toThrow(/first-capture-wins/);
  });

  it("--additional (`additional: true`) allows a second capture, stored with recorded: false — the first stays recorded: true", async () => {
    const outDir = path.join(OUT_DIR, "additional-run");
    const file1 = writeFixtureHtml("tn-add-1.html", "<h1>First capture</h1>");
    const first = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file1,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
    });
    expect(first.entry.recorded).toBe(true);

    const file2 = writeFixtureHtml(
      "tn-add-2.html",
      "<h1>Second capture, different bytes</h1>",
    );
    const second = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file2,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
      additional: true,
    });
    expect(second.entry.recorded).toBe(false);
    expect(second.manifest.trails.TN).toHaveLength(2);
    expect(second.manifest.trails.TN?.[0]?.recorded).toBe(true);
    expect(second.manifest.trails.TN?.[1]?.recorded).toBe(false);
  });

  it("a capture of a DIFFERENT URL for the same trail is unaffected by first-capture-wins", async () => {
    const outDir = path.join(OUT_DIR, "different-url-run");
    const file1 = writeFixtureHtml("tn-diff-1.html", "<h1>Golf page</h1>");
    await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file1,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
    });
    const file2 = writeFixtureHtml("tn-diff-2.html", "<h1>Rules page</h1>");
    const second = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file2,
      statedUrl: "https://tngolftrail.net/",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
    });
    expect(second.entry.recorded).toBe(true);
  });
});

describe("x2-ingest: gate findings — 10 MB file cap, extract-before-write ordering, __proto__, generatedAt", () => {
  it("refuses a file over the 10 MB cap, checked via stat before reading it into memory", async () => {
    const bigPath = path.join(OUT_DIR, "tn-huge.html");
    writeFileSync(bigPath, Buffer.alloc(10 * 1024 * 1024 + 1, "a"));
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: bigPath,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "huge-file-run"),
        ledgerPath: ledgerFor(path.join(OUT_DIR, "huge-file-run")),
      }),
    ).rejects.toThrow(/over the 10485760-byte cap/);
  });

  it("accepts a file right at the 10 MB cap", async () => {
    const atCapPath = path.join(OUT_DIR, "tn-at-cap.html");
    writeFileSync(atCapPath, Buffer.alloc(10 * 1024 * 1024, "a"));
    const { entry } = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: atCapPath,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir: path.join(OUT_DIR, "at-cap-run"),
      ledgerPath: ledgerFor(path.join(OUT_DIR, "at-cap-run")),
    });
    expect(entry.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("extracts text BEFORE writing the raw file — a bogus PDF (magic bytes but garbage body) that fails extraction leaves NO raw file behind", async () => {
    // Same scenario the gate's own probe (`ingest.mjs`) exercises: bytes
    // that LOOK like a PDF by magic number but are not a real, parseable
    // one — `extractPdfText` throws on this (its own documented contract).
    const pdfishPath = path.join(OUT_DIR, "tn-pdfish.pdf");
    writeFileSync(pdfishPath, "%PDF-1.4 garbage, not a real PDF");
    const outDir = path.join(OUT_DIR, "pdfish-run");
    await expect(
      ingestOwnerSavedPage({
        trail: "TN",
        filePath: pdfishPath,
        statedUrl: "https://www.tnstateparks.com/golf",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir,
        ledgerPath: ledgerFor(outDir),
      }),
    ).rejects.toThrow();
    // No raw/ directory should have been created at all — extraction ran
    // (and threw) strictly before any bytes were written to disk.
    expect(existsSync(path.join(outDir, "raw"))).toBe(false);
  });

  it('gate finding: rejects a `trail` of "__proto__" cleanly, before any object-key use', async () => {
    const file = writeFixtureHtml("proto.html", "<h1>x</h1>");
    await expect(
      ingestOwnerSavedPage({
        trail: "__proto__",
        filePath: file,
        statedUrl: "https://x.example/",
        statedDate: "2026-09-24",
        sourceConfig: TN_CONFIG,
        outDir: path.join(OUT_DIR, "proto-run"),
        ledgerPath: ledgerFor(path.join(OUT_DIR, "proto-run")),
      }),
    ).rejects.toThrow(/refused outright/);
    // The prototype of Object itself was never touched.
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('gate finding: rejects "constructor" and "prototype" as trail names too', async () => {
    const file = writeFixtureHtml("proto2.html", "<h1>x</h1>");
    for (const badTrail of ["constructor", "prototype"]) {
      await expect(
        ingestOwnerSavedPage({
          trail: badTrail,
          filePath: file,
          statedUrl: "https://x.example/",
          statedDate: "2026-09-24",
          sourceConfig: TN_CONFIG,
          outDir: path.join(OUT_DIR, `proto-run-${badTrail}`),
        }),
      ).rejects.toThrow(/refused outright/);
    }
  });

  it("gate finding: does NOT rewrite the manifest's own original generatedAt when merging a new capture in", async () => {
    const outDir = path.join(OUT_DIR, "generatedat-run");
    const file1 = writeFixtureHtml("tn-gen-1.html", "<h1>First</h1>");
    const first = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file1,
      statedUrl: "https://www.tnstateparks.com/golf",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
    });
    const originalGeneratedAt = first.manifest.generatedAt;

    // A real, later ingestion — generatedAt must NOT jump forward.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const file2 = writeFixtureHtml("tn-gen-2.html", "<h1>Second</h1>");
    const second = await ingestOwnerSavedPage({
      trail: "TN",
      filePath: file2,
      statedUrl: "https://tngolftrail.net/",
      statedDate: "2026-09-24",
      sourceConfig: TN_CONFIG,
      outDir,
      ledgerPath: ledgerFor(outDir),
    });
    expect(second.manifest.generatedAt).toBe(originalGeneratedAt);

    const onDisk = JSON.parse(
      readFileSync(path.join(outDir, "manifest.json"), "utf8"),
    ) as X2FetchManifest;
    expect(onDisk.generatedAt).toBe(originalGeneratedAt);
  });
});
