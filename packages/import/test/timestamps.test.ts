import { describe, expect, it } from "vitest";
import { parseStrictTimestamp, localDateForTz } from "../src/timestamps.js";

describe("parseStrictTimestamp: calendar-date validation (round 2 should-fix)", () => {
  it("accepts a real date", () => {
    const result = parseStrictTimestamp("2026-02-28T14:00:00+02:00");
    expect(result).toBeDefined();
    expect(result?.literalDate).toBe("2026-02-28");
  });

  it("rejects Feb 30 — Date.parse silently rolls this over to March 2nd; parseStrictTimestamp must not", () => {
    // Confirmed directly: Date.parse("2026-02-30T14:00:00Z") does NOT
    // return NaN, it returns a valid timestamp for March 2nd — so this
    // is a real gap parseStrictTimestamp has to close itself, not
    // something `Date.parse`'s own strict-ISO handling already covers.
    expect(Number.isFinite(Date.parse("2026-02-30T14:00:00Z"))).toBe(true);
    expect(parseStrictTimestamp("2026-02-30T14:00:00+02:00")).toBeUndefined();
    expect(parseStrictTimestamp("2026-02-30T14:00:00Z")).toBeUndefined();
  });

  it("rejects Feb 30 on a leap year too (2024 is a leap year; Feb still only has 29 days)", () => {
    expect(parseStrictTimestamp("2024-02-30T14:00:00Z")).toBeUndefined();
  });

  it("accepts Feb 29 on a leap year", () => {
    expect(parseStrictTimestamp("2024-02-29T14:00:00Z")).toBeDefined();
  });

  it("rejects Feb 29 on a non-leap year", () => {
    expect(parseStrictTimestamp("2026-02-29T14:00:00Z")).toBeUndefined();
  });

  it("rejects April 31 (a real month with only 30 days)", () => {
    expect(parseStrictTimestamp("2026-04-31T14:00:00Z")).toBeUndefined();
  });

  it("rejects a year before 2000", () => {
    expect(parseStrictTimestamp("1999-12-31T23:59:59Z")).toBeUndefined();
  });

  it("rejects a naive time (no Z/offset)", () => {
    expect(parseStrictTimestamp("2026-06-01T14:00:00")).toBeUndefined();
  });

  it("rejects a non-ISO string", () => {
    expect(parseStrictTimestamp("June 1 2026 2:00 PM")).toBeUndefined();
  });

  it("rejects a bare epoch number", () => {
    expect(parseStrictTimestamp("1780000000000")).toBeUndefined();
  });

  it("distinguishes a numeric offset (hasExplicitOffset: true) from Z (false)", () => {
    expect(parseStrictTimestamp("2026-06-01T10:00:00-04:00")?.hasExplicitOffset).toBe(true);
    expect(parseStrictTimestamp("2026-06-01T14:00:00Z")?.hasExplicitOffset).toBe(false);
  });

  it("literalDate uses the string's own written date, not the UTC-converted one", () => {
    // 23:30 in +02:00 is 21:30 UTC the same day — but a time that
    // crosses midnight through the offset conversion is the case this
    // guards: 01:00+02:00 is still 2026-06-01, but 23:00Z the day
    // before in UTC.
    const result = parseStrictTimestamp("2026-06-01T01:00:00+02:00");
    expect(result?.literalDate).toBe("2026-06-01");
  });
});

describe("localDateForTz", () => {
  it("converts a UTC instant into an IANA timezone's local date", () => {
    // 2026-06-02T02:00:00Z is 2026-06-01T22:00 EDT (UTC-4).
    const ms = Date.parse("2026-06-02T02:00:00Z");
    expect(localDateForTz(ms, "America/Toronto")).toBe("2026-06-01");
  });

  it("returns undefined for a bogus timezone", () => {
    expect(localDateForTz(Date.now(), "Not/ARealZone")).toBeUndefined();
  });
});
