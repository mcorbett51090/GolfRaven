import { describe, expect, it } from "vitest";
import {
  capAndSortFixes,
  checkInputSize,
  finalizeError,
  finalizeWarnings,
  isValidLat,
  isValidLon,
  isValidTimestamp,
  MAX_ECHO_CHARS,
  MAX_FIT_INPUT_BYTES,
  MAX_FIXES,
  MAX_INPUT_BYTES,
  MAX_WARNINGS,
  parseStrictDecimal,
  sanitizeAccuracy,
  sanitizeText,
  truncateEcho,
} from "../src/safety.js";

describe("checkInputSize", () => {
  it("passes for a small input", () => {
    expect(checkInputSize(1024)).toBeUndefined();
  });
  it("rejects an input over the (default 20 MB) cap", () => {
    expect(checkInputSize(MAX_INPUT_BYTES + 1)).toBeDefined();
  });
  it("supports a smaller explicit cap (the FIT 5 MB cap)", () => {
    expect(checkInputSize(MAX_FIT_INPUT_BYTES, MAX_FIT_INPUT_BYTES)).toBeUndefined();
    expect(checkInputSize(MAX_FIT_INPUT_BYTES + 1, MAX_FIT_INPUT_BYTES)).toBeDefined();
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

describe("parseStrictDecimal", () => {
  it("accepts plain decimals, including negative and fractional", () => {
    expect(parseStrictDecimal("43.65")).toBe(43.65);
    expect(parseStrictDecimal("-79.38")).toBe(-79.38);
    expect(parseStrictDecimal("0")).toBe(0);
    expect(parseStrictDecimal("  12.5  ")).toBe(12.5);
  });

  it("never turns an empty string into 0", () => {
    expect(parseStrictDecimal("")).toBeUndefined();
    expect(parseStrictDecimal("   ")).toBeUndefined();
  });

  it("rejects hex", () => {
    expect(parseStrictDecimal("0x10")).toBeUndefined();
  });

  it("rejects scientific notation", () => {
    expect(parseStrictDecimal("1e1")).toBeUndefined();
  });

  it("rejects a leading +", () => {
    expect(parseStrictDecimal("+43.65")).toBeUndefined();
  });

  it("rejects garbage", () => {
    expect(parseStrictDecimal("not-a-number")).toBeUndefined();
    expect(parseStrictDecimal("43.65.1")).toBeUndefined();
  });
});

describe("sanitizeAccuracy", () => {
  it("passes through a positive value", () => {
    expect(sanitizeAccuracy(5)).toBe(5);
  });
  it("turns 0 or negative into undefined", () => {
    expect(sanitizeAccuracy(0)).toBeUndefined();
    expect(sanitizeAccuracy(-5)).toBeUndefined();
  });
  it("turns undefined/non-finite into undefined", () => {
    expect(sanitizeAccuracy(undefined)).toBeUndefined();
    expect(sanitizeAccuracy(NaN)).toBeUndefined();
    expect(sanitizeAccuracy(Infinity)).toBeUndefined();
  });
});

describe("sanitizeText", () => {
  it("strips control characters", () => {
    expect(sanitizeText("Pinehill\u0000 Links\u0007")).toBe("Pinehill Links");
  });
  it("caps length", () => {
    expect(sanitizeText("a".repeat(200)).length).toBe(120);
  });
  it("trims whitespace", () => {
    expect(sanitizeText("  Pinehill Links  ")).toBe("Pinehill Links");
  });
});

describe("truncateEcho / finalizeError", () => {
  it("truncates to MAX_ECHO_CHARS by default", () => {
    const long = "x".repeat(200);
    expect(truncateEcho(long).length).toBe(MAX_ECHO_CHARS + 1); // +1 for the ellipsis
  });
  it("leaves a short string alone", () => {
    expect(truncateEcho("short")).toBe("short");
  });
  it("finalizeError truncates too", () => {
    expect(finalizeError("x".repeat(200)).length).toBe(MAX_ECHO_CHARS + 1);
  });
});

describe("finalizeWarnings", () => {
  it("passes through a short list unchanged in count", () => {
    const result = finalizeWarnings(["a", "b", "c"]);
    expect(result).toEqual(["a", "b", "c"]);
  });

  it("caps at MAX_WARNINGS plus one 'N more' entry", () => {
    const many = Array.from({ length: MAX_WARNINGS + 25 }, (_, i) => `warning ${i}`);
    const result = finalizeWarnings(many);
    expect(result).toHaveLength(MAX_WARNINGS + 1);
    expect(result[MAX_WARNINGS]).toContain("25");
    expect(result[MAX_WARNINGS]).toContain("more");
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
