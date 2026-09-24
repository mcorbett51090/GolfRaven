/**
 * `parseCsvRows`'s row cap (Opus security gate follow-up). A 19.9 MB
 * file of ~9.9 million empty rows (`,\n` repeated) — well under the
 * 20 MB CSV size cap — took **17.8 seconds** to tokenize before this
 * cap existed: millions of tiny row/array allocations, not any single
 * large field, was the actual cost. `parseCsvRows` now stops scanning
 * the moment it would produce more than `maxRows` rows.
 */
import { describe, expect, it } from "vitest";
import { parseCsvRows } from "../src/csv-rows.js";
import { MAX_CSV_ROWS } from "../src/safety.js";

describe("parseCsvRows: row cap", () => {
  it("stops scanning early and reports truncated, well before reading the whole input", () => {
    // The flood shape from the security gate's probe, scaled down for a
    // fast test but still well over the cap: empty rows.
    const rowCount = MAX_CSV_ROWS + 50_000;
    const text = ",\n".repeat(rowCount);
    const t0 = performance.now();
    const { rows, truncated } = parseCsvRows(text, MAX_CSV_ROWS);
    const elapsedMs = performance.now() - t0;

    expect(truncated).toBe(true);
    expect(rows.length).toBeLessThanOrEqual(MAX_CSV_ROWS);
    // Scanning stopped near the cap, not after consuming the whole
    // ~2×-the-cap input — a loose proxy, but the real regression (17.8s
    // on ~9.9M rows) is orders of magnitude slower than this bound.
    expect(elapsedMs).toBeLessThan(2000);
  });

  it("does not truncate a file within the cap", () => {
    const text = "a,b\n".repeat(1000);
    const { rows, truncated } = parseCsvRows(text, MAX_CSV_ROWS);
    expect(truncated).toBe(false);
    expect(rows).toHaveLength(1000);
  });

  it("with no cap given, behaves as before (unbounded)", () => {
    const { rows, truncated } = parseCsvRows("a,b\nc,d\n");
    expect(truncated).toBe(false);
    expect(rows).toEqual([
      ["a", "b"],
      ["c", "d"],
    ]);
  });

  it("still handles RFC 4180 quoting correctly under a cap", () => {
    const { rows, truncated } = parseCsvRows('a,"b,c"\n"d""e",f\n', 10);
    expect(truncated).toBe(false);
    expect(rows).toEqual([
      ["a", "b,c"],
      ['d"e', "f"],
    ]);
  });
});
