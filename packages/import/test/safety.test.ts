import { describe, expect, it } from "vitest";
import { capAndSortFixes, checkInputSize, isValidLat, isValidLon, isValidTimestamp, MAX_FIXES } from "../src/safety.js";

describe("checkInputSize", () => {
  it("passes for a small input", () => {
    expect(checkInputSize(1024)).toBeUndefined();
  });
  it("rejects an input over the cap", () => {
    expect(checkInputSize(20 * 1024 * 1024 + 1)).toBeDefined();
  });
});

describe("coordinate validation", () => {
  it("rejects non-finite and out-of-range values", () => {
    expect(isValidLat(NaN)).toBe(false);
    expect(isValidLat(Infinity)).toBe(false);
    expect(isValidLat(91)).toBe(false);
    expect(isValidLat(-91)).toBe(false);
    expect(isValidLat(45)).toBe(true);
    expect(isValidLon(181)).toBe(false);
    expect(isValidLon(-181)).toBe(false);
    expect(isValidLon(-79)).toBe(true);
    expect(isValidTimestamp(NaN)).toBe(false);
    expect(isValidTimestamp(Date.now())).toBe(true);
  });
});

describe("capAndSortFixes", () => {
  it("sorts ascending by timestamp, stably for ties", () => {
    const fixes = [
      { lat: 1, lon: 1, timestamp: 300, tag: "c" },
      { lat: 1, lon: 1, timestamp: 100, tag: "a" },
      { lat: 1, lon: 1, timestamp: 100, tag: "a2" },
      { lat: 1, lon: 1, timestamp: 200, tag: "b" },
    ];
    const { fixes: sorted, warnings } = capAndSortFixes(fixes);
    expect(sorted.map((f) => f.tag)).toEqual(["a", "a2", "b", "c"]);
    expect(warnings).toEqual([]);
  });

  it("truncates to MAX_FIXES with a warning", () => {
    const fixes = Array.from({ length: MAX_FIXES + 10 }, (_, i) => ({ lat: 0, lon: 0, timestamp: i }));
    const { fixes: capped, warnings } = capAndSortFixes(fixes);
    expect(capped).toHaveLength(MAX_FIXES);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(String(MAX_FIXES));
  });
});
