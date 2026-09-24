import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  corroborateWayback,
  daysBetween,
  parseWaybackUrl,
  waybackTimestampToDate,
  WAYBACK_TIMESTAMP_TOLERANCE_DAYS,
  type WaybackFetcher,
} from "../src/x2-corroborate-wayback.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-wayback-test-"));
const LEDGER_PATH = path.join(OUT_DIR, "ledger.json");

describe("x2-corroborate-wayback: parseWaybackUrl (gate finding 3, re-gate)", () => {
  it("accepts the exact required form", () => {
    const result = parseWaybackUrl(
      "https://web.archive.org/web/20260615120000/https://example.com/golf",
    );
    expect(result).toEqual({
      timestamp: "20260615120000",
      embeddedUrl: "https://example.com/golf",
    });
  });

  it("refuses a non-web.archive.org host", () => {
    expect(
      parseWaybackUrl("https://not-archive.example/web/20260615120000/https://example.com/golf"),
    ).toBeNull();
  });

  it("refuses a missing/short timestamp", () => {
    expect(
      parseWaybackUrl("https://web.archive.org/web/202606151200/https://example.com/golf"),
    ).toBeNull();
  });

  it("refuses a Wayback URL with a flag suffix on the timestamp (e.g. id_) — deliberately not widened", () => {
    expect(
      parseWaybackUrl("https://web.archive.org/web/20260615120000id_/https://example.com/golf"),
    ).toBeNull();
  });

  it("refuses http (non-https)", () => {
    expect(
      parseWaybackUrl("http://web.archive.org/web/20260615120000/https://example.com/golf"),
    ).toBeNull();
  });

  it("refuses a URL missing the embedded URL entirely", () => {
    expect(parseWaybackUrl("https://web.archive.org/web/20260615120000/")).toBeNull();
  });
});

describe("x2-corroborate-wayback: waybackTimestampToDate / daysBetween", () => {
  it("parses a real 14-digit timestamp as UTC", () => {
    const d = waybackTimestampToDate("20260615120000");
    expect(d.toISOString()).toBe("2026-06-15T12:00:00.000Z");
  });

  it("refuses a syntactically-14-digit but impossible date (month 13)", () => {
    expect(() => waybackTimestampToDate("20261315120000")).toThrow(/not a real calendar/);
  });

  it("daysBetween is symmetric and correct for a known gap", () => {
    const a = new Date("2026-01-01T00:00:00Z");
    const b = new Date("2026-01-11T00:00:00Z");
    expect(daysBetween(a, b)).toBe(10);
    expect(daysBetween(b, a)).toBe(10);
  });
});

function fakeFetcher(opts: { status?: number; body: string }): WaybackFetcher {
  return async () => ({
    status: opts.status ?? 200,
    ok: (opts.status ?? 200) >= 200 && (opts.status ?? 200) < 300,
    async arrayBuffer() {
      return new TextEncoder().encode(opts.body).buffer;
    },
  });
}

describe("x2-corroborate-wayback: corroborateWayback (gate finding 3, re-gate — the real pipeline)", () => {
  const GOOD_URL = "https://web.archive.org/web/20260615120000/https://example.com/golf";

  it("refuses a malformed archive URL before ever fetching anything", async () => {
    let called = false;
    const fetcher: WaybackFetcher = async () => {
      called = true;
      throw new Error("should never be called");
    };
    await expect(
      corroborateWayback({
        archiveUrl: "https://not-archive.example/whatever",
        statedUrl: "https://example.com/golf",
        ownerSavedDate: "2026-06-15",
        outDir: path.join(OUT_DIR, "bad-url-run"),
        ledgerPath: LEDGER_PATH,
        fetcher,
      }),
    ).rejects.toThrow(/not a Wayback snapshot URL/);
    expect(called).toBe(false);
  });

  it("refuses when the embedded URL does NOT normalise to the same thing as --stated-url — a snapshot of a DIFFERENT page can never corroborate", async () => {
    let called = false;
    const fetcher: WaybackFetcher = async () => {
      called = true;
      throw new Error("should never be called");
    };
    await expect(
      corroborateWayback({
        archiveUrl: GOOD_URL,
        statedUrl: "https://example.com/completely-different-page",
        ownerSavedDate: "2026-06-15",
        outDir: path.join(OUT_DIR, "mismatch-run"),
        ledgerPath: LEDGER_PATH,
        fetcher,
      }),
    ).rejects.toThrow(/does not match --stated-url/);
    expect(called).toBe(false);
  });

  it("accepts a bypass-shaped VARIANT of the stated URL (normalises to the same thing)", async () => {
    const fetcher = fakeFetcher({ body: "<p>The corroborating quote is right here.</p>" });
    const record = await corroborateWayback({
      archiveUrl: "https://web.archive.org/web/20260615120000/https://www.example.com/golf/",
      statedUrl: "https://example.com/golf",
      ownerSavedDate: "2026-06-15",
      outDir: path.join(OUT_DIR, "variant-run"),
      ledgerPath: LEDGER_PATH,
      fetcher,
    });
    expect(record.type).toBe("wayback");
  });

  it(`refuses a timestamp more than ${WAYBACK_TIMESTAMP_TOLERANCE_DAYS} days from --owner-saved-date`, async () => {
    let called = false;
    const fetcher: WaybackFetcher = async () => {
      called = true;
      throw new Error("should never be called");
    };
    await expect(
      corroborateWayback({
        archiveUrl: GOOD_URL, // 2026-06-15
        statedUrl: "https://example.com/golf",
        ownerSavedDate: "2024-01-01", // wildly different
        outDir: path.join(OUT_DIR, "stale-run"),
        ledgerPath: LEDGER_PATH,
        fetcher,
      }),
    ).rejects.toThrow(/outside the 90-day tolerance/);
    expect(called).toBe(false);
  });

  it("accepts a timestamp well within the tolerance window", async () => {
    const fetcher = fakeFetcher({ body: "<p>within tolerance ok</p>" });
    // GOOD_URL's timestamp is 2026-06-15; 89 days prior is comfortably
    // inside the 90-day window regardless of time-of-day rounding.
    const record = await corroborateWayback({
      archiveUrl: GOOD_URL,
      statedUrl: "https://example.com/golf",
      ownerSavedDate: "2026-03-18",
      outDir: path.join(OUT_DIR, "boundary-run"),
      ledgerPath: LEDGER_PATH,
      fetcher,
    });
    expect(record.snapshotSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses (surfaces) a non-2xx response from the fetch", async () => {
    const fetcher = fakeFetcher({ status: 404, body: "not found" });
    await expect(
      corroborateWayback({
        archiveUrl: GOOD_URL,
        statedUrl: "https://example.com/golf",
        ownerSavedDate: "2026-06-15",
        outDir: path.join(OUT_DIR, "404-run"),
        ledgerPath: LEDGER_PATH,
        fetcher,
      }),
    ).rejects.toThrow(/HTTP 404/);
  });

  it("surfaces a fetch failure (e.g. connectivity) with a clear message, never silently fabricating evidence", async () => {
    const fetcher: WaybackFetcher = async () => {
      throw new Error("connect timeout");
    };
    await expect(
      corroborateWayback({
        archiveUrl: GOOD_URL,
        statedUrl: "https://example.com/golf",
        ownerSavedDate: "2026-06-15",
        outDir: path.join(OUT_DIR, "fetch-fail-run"),
        ledgerPath: LEDGER_PATH,
        fetcher,
      }),
    ).rejects.toThrow(/fetching the Wayback snapshot failed/);
  });

  it("refuses a response over the byte cap", async () => {
    const fetcher = fakeFetcher({ body: "x".repeat(11 * 1024 * 1024) });
    await expect(
      corroborateWayback({
        archiveUrl: GOOD_URL,
        statedUrl: "https://example.com/golf",
        ownerSavedDate: "2026-06-15",
        outDir: path.join(OUT_DIR, "oversized-run"),
        ledgerPath: LEDGER_PATH,
        fetcher,
        maxBytes: 10 * 1024 * 1024,
      }),
    ).rejects.toThrow(/over the \d+-byte cap/);
  });

  it("on success: stores the ACTUAL fetched bytes as evidence, computes the SHA over them, and the returned record cites only the SHA/rawFile — no inline text", async () => {
    const body = "<html><body><p>Vancouver Island Golf Trail. Arbutus Ridge is a member course.</p></body></html>";
    const fetcher = fakeFetcher({ body });
    const outDir = path.join(OUT_DIR, "success-run");
    const record = await corroborateWayback({
      archiveUrl: GOOD_URL,
      statedUrl: "https://example.com/golf",
      ownerSavedDate: "2026-06-15",
      outDir,
      ledgerPath: LEDGER_PATH,
      fetcher,
    });
    expect(record).toEqual({
      type: "wayback",
      snapshotUrl: GOOD_URL,
      snapshotSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      rawFile: expect.stringContaining("raw"),
    });
    expect("snapshotText" in record).toBe(false);

    const rawOnDisk = readFileSync(path.join(outDir, record.rawFile), "utf8");
    expect(rawOnDisk).toBe(body);

    const { createHash } = await import("node:crypto");
    const recomputed = createHash("sha256").update(Buffer.from(body)).digest("hex");
    expect(record.snapshotSha256).toBe(recomputed);
  });
});
