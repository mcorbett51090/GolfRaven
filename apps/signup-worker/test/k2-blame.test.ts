import { describe, expect, it } from "vitest";
import { resolveK2Exclusions, type BlameLine } from "../src/k2-blame";

const DAY0 = "2026-10-05";
const DAY0_LINE = 10;

function blameMap(entries: Record<number, BlameLine>): Map<number, BlameLine> {
  return new Map(Object.entries(entries).map(([line, blame]) => [Number(line), blame]));
}

describe("resolveK2Exclusions", () => {
  it("refuses when Day 0's own line has no committed blame", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [],
      blameByLine: blameMap({ [DAY0_LINE]: { authorTimeIso: null } }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/not committed/);
  });

  it("refuses when Day 0's own line is entirely missing from the blame map", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [],
      blameByLine: new Map(),
    });
    expect(result.ok).toBe(false);
  });

  it("excludes an address whose line was committed strictly before day 0 00:00 UTC", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [{ address: "matt@golfraven.example", line: 20 }],
      blameByLine: blameMap({
        [DAY0_LINE]: { authorTimeIso: "2026-10-04T12:00:00.000Z" },
        20: { authorTimeIso: "2026-09-30T00:00:00.000Z" },
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.excluded).toEqual(["matt@golfraven.example"]);
      expect(result.notExcluded).toEqual([]);
    }
  });

  it("does NOT exclude an address added on day 0 itself (not strictly before)", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [{ address: "sameday@golfraven.example", line: 20 }],
      blameByLine: blameMap({
        [DAY0_LINE]: { authorTimeIso: "2026-10-04T12:00:00.000Z" },
        20: { authorTimeIso: "2026-10-05T00:00:00.000Z" }, // exactly day0 00:00 UTC
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.excluded).toEqual([]);
      expect(result.notExcluded).toEqual([
        { address: "sameday@golfraven.example", line: 20, note: "not excluded (added on/after day 0 or uncommitted)" },
      ]);
    }
  });

  it("does NOT exclude an address added after day 0 — this is exactly R3's retroactive-exclusion rule", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [{ address: "late@golfraven.example", line: 25 }],
      blameByLine: blameMap({
        [DAY0_LINE]: { authorTimeIso: "2026-10-04T12:00:00.000Z" },
        25: { authorTimeIso: "2026-10-06T00:00:00.000Z" },
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.excluded).toEqual([]);
      expect(result.notExcluded[0]?.address).toBe("late@golfraven.example");
    }
  });

  it("does NOT exclude an address whose line is uncommitted (working-tree only)", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [{ address: "uncommitted@golfraven.example", line: 30 }],
      blameByLine: blameMap({
        [DAY0_LINE]: { authorTimeIso: "2026-10-04T12:00:00.000Z" },
        30: { authorTimeIso: null },
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.excluded).toEqual([]);
      expect(result.notExcluded[0]?.note).toBe("not excluded (added on/after day 0 or uncommitted)");
    }
  });

  it("dedupes an address that appears on more than one qualifying line", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [
        { address: "dup@golfraven.example", line: 20 },
        { address: "dup@golfraven.example", line: 21 },
      ],
      blameByLine: blameMap({
        [DAY0_LINE]: { authorTimeIso: "2026-10-04T12:00:00.000Z" },
        20: { authorTimeIso: "2026-09-30T00:00:00.000Z" },
        21: { authorTimeIso: "2026-09-30T00:00:00.000Z" },
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.excluded).toEqual(["dup@golfraven.example"]);
  });

  it("handles a mix: some excluded, some not, in entry order for the excluded list", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      day0Line: DAY0_LINE,
      entries: [
        { address: "before@golfraven.example", line: 20 },
        { address: "after@golfraven.example", line: 21 },
        { address: "before2@golfraven.example", line: 22 },
      ],
      blameByLine: blameMap({
        [DAY0_LINE]: { authorTimeIso: "2026-10-04T12:00:00.000Z" },
        20: { authorTimeIso: "2026-09-28T00:00:00.000Z" },
        21: { authorTimeIso: "2026-10-07T00:00:00.000Z" },
        22: { authorTimeIso: "2026-09-29T00:00:00.000Z" },
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.excluded).toEqual(["before@golfraven.example", "before2@golfraven.example"]);
      expect(result.notExcluded.map((e) => e.address)).toEqual(["after@golfraven.example"]);
    }
  });
});
