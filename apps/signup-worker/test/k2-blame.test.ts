import { describe, expect, it } from "vitest";
import { resolveK2Exclusions, type FirstAppearance } from "../src/k2-blame";

const DAY0 = "2026-10-05";

function firstAppearanceMap(entries: Record<string, FirstAppearance>): Map<string, FirstAppearance> {
  return new Map(Object.entries(entries));
}

describe("resolveK2Exclusions (decision 0001 Addendum F — first-appearance, committer-time dating)", () => {
  it("excludes an address whose first appearance was committed strictly before day 0 00:00 UTC", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      entries: [{ address: "matt@golfraven.example", line: 20 }],
      firstAppearanceByAddress: firstAppearanceMap({
        "matt@golfraven.example": { committerTimeIso: "2026-09-30T00:00:00.000Z" },
      }),
    });
    expect(result.excluded).toEqual(["matt@golfraven.example"]);
    expect(result.notExcluded).toEqual([]);
  });

  it("does NOT exclude an address first appearing on day 0 itself (not strictly before)", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      entries: [{ address: "sameday@golfraven.example", line: 20 }],
      firstAppearanceByAddress: firstAppearanceMap({
        "sameday@golfraven.example": { committerTimeIso: "2026-10-05T00:00:00.000Z" }, // exactly day0 00:00 UTC
      }),
    });
    expect(result.excluded).toEqual([]);
    expect(result.notExcluded).toEqual([
      {
        address: "sameday@golfraven.example",
        line: 20,
        note: "not excluded (first committed on/after day 0, or no commit history found)",
      },
    ]);
  });

  it("does NOT exclude an address first appearing after day 0", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      entries: [{ address: "late@golfraven.example", line: 25 }],
      firstAppearanceByAddress: firstAppearanceMap({
        "late@golfraven.example": { committerTimeIso: "2026-10-06T00:00:00.000Z" },
      }),
    });
    expect(result.excluded).toEqual([]);
    expect(result.notExcluded[0]?.address).toBe("late@golfraven.example");
  });

  it("does NOT exclude an address with no first-appearance data at all (git log -S found nothing)", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      entries: [{ address: "nohistory@golfraven.example", line: 30 }],
      firstAppearanceByAddress: firstAppearanceMap({}),
    });
    expect(result.excluded).toEqual([]);
    expect(result.notExcluded[0]?.note).toBe("not excluded (first committed on/after day 0, or no commit history found)");
  });

  it("gate finding A-5 (a): a LATER REFORMAT of the line does not change the first-appearance date — still excluded", () => {
    // git log -S returns the EARLIEST commit whose diff changed the
    // occurrence count of the address string — a pure reformat (backticks,
    // whitespace) around an unchanged address does not change that count,
    // so the caller's `git log -S` call itself never surfaces the reformat
    // commit here at all; this module just sees the (unaffected) original
    // first-appearance time.
    const result = resolveK2Exclusions({
      day0: DAY0,
      entries: [{ address: "a@x.com", line: 15 }], // line moved/reformatted by a later commit
      firstAppearanceByAddress: firstAppearanceMap({
        "a@x.com": { committerTimeIso: "2026-09-30T00:00:00.000Z" }, // unaffected by the reformat
      }),
    });
    expect(result.excluded).toEqual(["a@x.com"]);
  });

  it("dedupes an address that appears on more than one entry line", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      entries: [
        { address: "dup@golfraven.example", line: 20 },
        { address: "dup@golfraven.example", line: 21 },
      ],
      firstAppearanceByAddress: firstAppearanceMap({
        "dup@golfraven.example": { committerTimeIso: "2026-09-30T00:00:00.000Z" },
      }),
    });
    expect(result.excluded).toEqual(["dup@golfraven.example"]);
  });

  it("handles a mix: some excluded, some not, in entry order for the excluded list", () => {
    const result = resolveK2Exclusions({
      day0: DAY0,
      entries: [
        { address: "before@golfraven.example", line: 20 },
        { address: "after@golfraven.example", line: 21 },
        { address: "before2@golfraven.example", line: 22 },
      ],
      firstAppearanceByAddress: firstAppearanceMap({
        "before@golfraven.example": { committerTimeIso: "2026-09-28T00:00:00.000Z" },
        "after@golfraven.example": { committerTimeIso: "2026-10-07T00:00:00.000Z" },
        "before2@golfraven.example": { committerTimeIso: "2026-09-29T00:00:00.000Z" },
      }),
    });
    expect(result.excluded).toEqual(["before@golfraven.example", "before2@golfraven.example"]);
    expect(result.notExcluded.map((e) => e.address)).toEqual(["after@golfraven.example"]);
  });
});
