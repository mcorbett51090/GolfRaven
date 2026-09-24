import { describe, expect, it } from "vitest";
import { correlationKey } from "../src/correlation.js";
import type { ImportedRound } from "../src/types.js";

function routeRound(startedAt: number | undefined): ImportedRound {
  return {
    source: "file_import",
    format: "gpx",
    fixes:
      startedAt !== undefined
        ? [{ lat: 43.65, lon: -79.38, timestamp: startedAt }]
        : [],
    warnings: [],
    ...(startedAt !== undefined ? { startedAt } : {}),
  };
}

function routelessRound(): ImportedRound {
  return {
    source: "file_import",
    format: "csv",
    fixes: [],
    warnings: [],
    localDate: "2026-06-01",
  };
}

function shareKey(a: string[] | undefined, b: string[] | undefined): boolean {
  if (!a || !b) return false;
  return a.some((k) => b.includes(k));
}

describe("correlationKey", () => {
  it("is undefined when the round has no startedAt", () => {
    expect(correlationKey(routeRound(undefined), "fac_1")).toBeUndefined();
  });

  it("is undefined for a routeless (localDate-only) round even if it somehow carried a startedAt", () => {
    const round = routelessRound();
    expect(correlationKey(round, "fac_1")).toBeUndefined();
  });

  it("returns exactly 3 keys: previous, current, next bucket", () => {
    const base = Date.parse("2026-06-01T14:00:00Z");
    const keys = correlationKey(routeRound(base), "fac_1");
    expect(keys).toHaveLength(3);
    const floor = Math.floor(base / (15 * 60 * 1000));
    expect(keys).toEqual([
      `fac_1:${floor - 1}`,
      `fac_1:${floor}`,
      `fac_1:${floor + 1}`,
    ]);
  });

  it("shares a key for two rounds close together at the same facility", () => {
    const base = Date.parse("2026-06-01T14:00:00Z");
    const a = correlationKey(routeRound(base), "fac_1");
    const b = correlationKey(routeRound(base + 3 * 60_000), "fac_1");
    expect(shareKey(a, b)).toBe(true);
  });

  it("never shares a key across facilities, even at the same instant", () => {
    const base = Date.parse("2026-06-01T14:00:00Z");
    const a = correlationKey(routeRound(base), "fac_1");
    const b = correlationKey(routeRound(base), "fac_2");
    expect(shareKey(a, b)).toBe(false);
  });

  it("shares no key for rounds well outside the correlation window", () => {
    const base = Date.parse("2026-06-01T14:00:00Z");
    const a = correlationKey(routeRound(base), "fac_1");
    const b = correlationKey(routeRound(base + 3 * 3600_000), "fac_1");
    expect(shareKey(a, b)).toBe(false);
  });

  it("mutation-pinning: shares no key 90 minutes apart — catches a 60-minute-bucket mutation", () => {
    // With the correct 15-minute grid, 90 minutes = 6 buckets apart, well
    // outside the ±1-neighbor overlap. A mutant that widened the bucket
    // to 60 minutes would put these only 1 (60-minute) bucket apart,
    // which *would* overlap under the ±1-neighbor scheme — so this test
    // fails under that mutation and passes under the real 15-minute one.
    // Clock-aligned timestamps (both grids share epoch-0 alignment) keep
    // the bucket arithmetic exact rather than alignment-dependent.
    const a = correlationKey(
      routeRound(Date.parse("2026-06-01T10:00:00Z")),
      "fac_1",
    );
    const b = correlationKey(
      routeRound(Date.parse("2026-06-01T11:30:00Z")),
      "fac_1",
    );
    expect(shareKey(a, b)).toBe(false);
  });

  describe("boundary cases", () => {
    it("shares a key 2 seconds apart, straddling a 15-minute grid line (10:07:29 vs 10:07:31)", () => {
      const a = correlationKey(
        routeRound(Date.parse("2026-06-01T10:07:29Z")),
        "fac_1",
      );
      const b = correlationKey(
        routeRound(Date.parse("2026-06-01T10:07:31Z")),
        "fac_1",
      );
      expect(shareKey(a, b)).toBe(true);
    });

    it("shares a key at exactly ±15 minutes", () => {
      const a = correlationKey(
        routeRound(Date.parse("2026-06-01T10:00:00Z")),
        "fac_1",
      );
      const b = correlationKey(
        routeRound(Date.parse("2026-06-01T10:15:00Z")),
        "fac_1",
      );
      expect(shareKey(a, b)).toBe(true);
    });

    it("shares a key at exactly ±15 minutes even when it lands on a grid boundary", () => {
      // 09:52:30 is mid-bucket; 10:07:30 is exactly 15 minutes later and
      // sits exactly on a grid boundary (floor jumps by 1 there).
      const a = correlationKey(
        routeRound(Date.parse("2026-06-01T09:52:30Z")),
        "fac_1",
      );
      const b = correlationKey(
        routeRound(Date.parse("2026-06-01T10:07:30Z")),
        "fac_1",
      );
      expect(shareKey(a, b)).toBe(true);
    });
  });
});
