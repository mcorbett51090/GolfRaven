import { describe, expect, it } from "vitest";
import { correlationKey } from "../src/correlation.js";
import type { ImportedRound } from "../src/types.js";

function roundStartedAt(startedAt: number | undefined): ImportedRound {
  return {
    source: "file_import",
    format: "gpx",
    fixes: [],
    warnings: [],
    ...(startedAt !== undefined ? { startedAt } : {}),
  };
}

describe("correlationKey", () => {
  it("is undefined when the round has no startedAt", () => {
    expect(correlationKey(roundStartedAt(undefined), "fac_1")).toBeUndefined();
  });

  it("is the same for two rounds close together at the same facility", () => {
    const base = Date.parse("2026-06-01T14:00:00Z");
    const a = correlationKey(roundStartedAt(base), "fac_1");
    const b = correlationKey(roundStartedAt(base + 3 * 60_000), "fac_1");
    expect(a).toBeDefined();
    expect(a).toBe(b);
  });

  it("differs across facilities even at the same time", () => {
    const base = Date.parse("2026-06-01T14:00:00Z");
    const a = correlationKey(roundStartedAt(base), "fac_1");
    const b = correlationKey(roundStartedAt(base), "fac_2");
    expect(a).not.toBe(b);
  });

  it("differs for rounds well outside the correlation window", () => {
    const base = Date.parse("2026-06-01T14:00:00Z");
    const a = correlationKey(roundStartedAt(base), "fac_1");
    const b = correlationKey(roundStartedAt(base + 3 * 3600_000), "fac_1");
    expect(a).not.toBe(b);
  });
});
