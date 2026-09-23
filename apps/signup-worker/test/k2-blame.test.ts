import { describe, expect, it } from "vitest";
import { resolveK2Exclusions, type FirstAppearance } from "../src/k2-blame";

const DAY0 = "2026-10-05";

function firstAppearanceMap(
  entries: Record<string, FirstAppearance>,
): Map<string, FirstAppearance> {
  return new Map(Object.entries(entries));
}

describe("resolveK2Exclusions (decision 0001 Addendum F + gate findings F-S2/F-S3 — full-history, exact-address dating)", () => {
  it("excludes an address whose first appearance was committed strictly before day 0 00:00 UTC", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [{ address: "matt@golfraven.example", line: 20 }],
      firstAppearanceByAddress: firstAppearanceMap({
        "matt@golfraven.example": {
          committerTimeIso: "2026-09-30T00:00:00.000Z",
        },
      }),
    });
    expect(result.excluded).toEqual(["matt@golfraven.example"]);
    expect(result.notExcluded).toEqual([]);
  });

  it("does NOT exclude an address first appearing on day 0 itself (not strictly before), and flags it (A-6)", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [{ address: "sameday@golfraven.example", line: 20 }],
      firstAppearanceByAddress: firstAppearanceMap({
        "sameday@golfraven.example": {
          committerTimeIso: "2026-10-05T00:00:00.000Z",
        }, // exactly day0 00:00 UTC
      }),
    });
    expect(result.excluded).toEqual([]);
    expect(result.excludedOnDay0).toEqual(["sameday@golfraven.example"]);
    expect(result.notExcluded).toEqual([
      {
        address: "sameday@golfraven.example",
        line: 20,
        note: "not excluded (first committed on/after day 0, or no commit history found)",
      },
    ]);
  });

  it("flags an address first appearing later on day 0 (23:59Z) as excludedOnDay0, not just before-midnight", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [{ address: "lateday@golfraven.example", line: 20 }],
      firstAppearanceByAddress: firstAppearanceMap({
        "lateday@golfraven.example": {
          committerTimeIso: "2026-10-05T23:59:59.000Z",
        },
      }),
    });
    expect(result.excluded).toEqual([]);
    expect(result.excludedOnDay0).toEqual(["lateday@golfraven.example"]);
  });

  it("does NOT exclude an address first appearing after day 0, and does not flag it as day-0", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [{ address: "late@golfraven.example", line: 25 }],
      firstAppearanceByAddress: firstAppearanceMap({
        "late@golfraven.example": {
          committerTimeIso: "2026-10-06T00:00:00.000Z",
        },
      }),
    });
    expect(result.excluded).toEqual([]);
    expect(result.excludedOnDay0).toEqual([]);
    expect(result.notExcluded[0]?.address).toBe("late@golfraven.example");
  });

  it("does NOT exclude an address with no first-appearance data at all", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [{ address: "nohistory@golfraven.example", line: 30 }],
      firstAppearanceByAddress: firstAppearanceMap({}),
    });
    expect(result.excluded).toEqual([]);
    expect(result.notExcluded[0]?.note).toBe(
      "not excluded (first committed on/after day 0, or no commit history found)",
    );
  });

  it("gate finding A-5: a LATER REFORMAT of the line does not change the first-appearance date — still excluded", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [{ address: "a@x.com", line: 15 }], // line moved/reformatted by a later commit
      firstAppearanceByAddress: firstAppearanceMap({
        "a@x.com": { committerTimeIso: "2026-09-30T00:00:00.000Z" }, // unaffected by the reformat
      }),
    });
    expect(result.excluded).toEqual(["a@x.com"]);
  });

  it("dedupes an address that appears on more than one entry line", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [
        { address: "dup@golfraven.example", line: 20 },
        { address: "dup@golfraven.example", line: 21 },
      ],
      firstAppearanceByAddress: firstAppearanceMap({
        "dup@golfraven.example": {
          committerTimeIso: "2026-09-30T00:00:00.000Z",
        },
      }),
    });
    expect(result.excluded).toEqual(["dup@golfraven.example"]);
    expect(result.notExcluded).toEqual([]);
  });

  it("handles a mix: some excluded, some not", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [
        { address: "before@golfraven.example", line: 20 },
        { address: "after@golfraven.example", line: 21 },
        { address: "before2@golfraven.example", line: 22 },
      ],
      firstAppearanceByAddress: firstAppearanceMap({
        "before@golfraven.example": {
          committerTimeIso: "2026-09-28T00:00:00.000Z",
        },
        "after@golfraven.example": {
          committerTimeIso: "2026-10-07T00:00:00.000Z",
        },
        "before2@golfraven.example": {
          committerTimeIso: "2026-09-29T00:00:00.000Z",
        },
      }),
    });
    expect(new Set(result.excluded)).toEqual(
      new Set(["before@golfraven.example", "before2@golfraven.example"]),
    );
    expect(result.notExcluded.map((e) => e.address)).toEqual([
      "after@golfraven.example",
    ]);
  });

  it("gate finding F-S2: an address excluded by history but no longer CURRENTLY listed is still excluded, and flagged", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [{ address: "still-here@golfraven.example", line: 5 }], // "deleted@..." is NOT in currentEntries
      firstAppearanceByAddress: firstAppearanceMap({
        "still-here@golfraven.example": {
          committerTimeIso: "2026-09-28T00:00:00.000Z",
        },
        "deleted@golfraven.example": {
          committerTimeIso: "2026-09-25T00:00:00.000Z",
        }, // deleted from K2.md after day 0
      }),
    });
    expect(new Set(result.excluded)).toEqual(
      new Set(["still-here@golfraven.example", "deleted@golfraven.example"]),
    );
    expect(result.excludedButNoLongerListed).toEqual([
      "deleted@golfraven.example",
    ]);
  });

  it("gate finding F-S3: exact whole-address identity — a first-appearance map keyed by full addresses never lets one substring-exclude another", () => {
    // ba@x.com is excluded (before day 0); a@x.com is a DIFFERENT address,
    // first appearing after day 0 — it must not be excluded even though
    // "a@x.com" is a substring of "ba@x.com".
    const result = resolveK2Exclusions({
      day0: DAY0,
      currentEntries: [
        { address: "ba@x.com", line: 5 },
        { address: "a@x.com", line: 6 },
      ],
      firstAppearanceByAddress: firstAppearanceMap({
        "ba@x.com": { committerTimeIso: "2026-09-28T00:00:00.000Z" },
        "a@x.com": { committerTimeIso: "2026-10-10T00:00:00.000Z" },
      }),
    });
    expect(result.excluded).toEqual(["ba@x.com"]);
    expect(result.notExcluded.map((e) => e.address)).toEqual(["a@x.com"]);
  });
});
