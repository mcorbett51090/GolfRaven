import { describe, expect, it } from "vitest";
import {
  computeK3Verdict,
  K3_SEARCH_CONSOLE_BAR,
  K3_KEYWORD_BAR,
  K3_CONSEQUENCE_BOTH_MISS,
  K3_CONSEQUENCE_DISAGREE,
  K3_CONSEQUENCE_UNIVERSAL,
} from "../src/k3-verdict.js";
import { K3_KEYWORD_TERMS, K3_SEARCH_CONSOLE_MONTHS, type K3Log, type K3KeywordRow } from "../src/k3-log.js";

function scRows(clicks: [number | null, number | null, number | null]) {
  return K3_SEARCH_CONSOLE_MONTHS.map((month, i) => ({ month, clicks: clicks[i]! }));
}

function kwRows(
  values: Record<
    string,
    { lowerBound?: number | null; upperBound?: number | null; pointValue?: number | null }
  >,
): K3KeywordRow[] {
  return K3_KEYWORD_TERMS.map((term) => {
    const v = values[term] ?? {};
    return {
      term,
      lowerBound: v.lowerBound ?? null,
      upperBound: v.upperBound ?? null,
      pointValue: v.pointValue ?? null,
    };
  });
}

function allPointValues(value: number): Record<string, { pointValue: number }> {
  const out: Record<string, { pointValue: number }> = {};
  for (const t of K3_KEYWORD_TERMS) out[t] = { pointValue: value };
  return out;
}

function buildLog(
  propertyId: string,
  clicks: [number | null, number | null, number | null],
  keywords: Record<string, { lowerBound?: number | null; upperBound?: number | null; pointValue?: number | null }>,
): K3Log {
  return { propertyId, searchConsole: scRows(clicks), keywords: kwRows(keywords) };
}

describe("computeK3Verdict: refusals", () => {
  it("refuses (throws) when the property id is blank", () => {
    const log = buildLog("", [1000, 1000, 1000], allPointValues(1000));
    expect(() => computeK3Verdict(log)).toThrow(/property id/);
  });

  it("refuses when a month's clicks total is blank", () => {
    const log = buildLog("prop-1", [1000, null, 1000], allPointValues(1000));
    expect(() => computeK3Verdict(log)).toThrow(/missing: 2026-08/);
  });

  it("refuses when a keyword term has neither a range nor a point value", () => {
    const values = allPointValues(1000);
    delete (values as Record<string, unknown>)["golf trail"];
    const log = buildLog("prop-1", [1000, 1000, 1000], values);
    expect(() => computeK3Verdict(log)).toThrow(/missing: golf trail/);
  });
});

describe("computeK3Verdict: Search Console median (decision 0001 Addendum A)", () => {
  it("takes the median of the three months regardless of input order", () => {
    // July=2000, August=500, September=1000 -> sorted [500, 1000, 2000] -> median 1000
    const log = buildLog("prop-1", [2000, 500, 1000], allPointValues(1000));
    const result = computeK3Verdict(log);
    expect(result.searchConsole.median).toBe(1000);
    expect(result.searchConsole.bar).toBe(K3_SEARCH_CONSOLE_BAR);
    expect(result.searchConsole.pass).toBe(true); // 1000 >= 1000 bar (boundary)
  });

  it("just under the bar fails", () => {
    const log = buildLog("prop-1", [999, 999, 999], allPointValues(1000));
    const result = computeK3Verdict(log);
    expect(result.searchConsole.pass).toBe(false);
  });
});

describe("computeK3Verdict: Keyword Planner — decision 0001 Addendum D R5 duplicate-range rule", () => {
  it("counts an identical range shared by two terms only once", () => {
    const log = buildLog("prop-1", [1000, 1000, 1000], {
      "golf trail": { lowerBound: 1000, upperBound: 1500 },
      "golf trails": { lowerBound: 1000, upperBound: 1500 }, // identical range -> dedup
      "robert trent jones golf trail": { pointValue: 100 },
      "tennessee golf trail": { pointValue: 100 },
      "vancouver island golf trail": { pointValue: 100 },
      "oklahoma golf trail": { pointValue: 100 },
    });
    const result = computeK3Verdict(log);
    // 1000 (once, not 2000) + 100*4 = 1400
    expect(result.keyword.combinedVolume).toBe(1400);
    const golfTrail = result.keyword.contributions.find((c) => c.term === "golf trail")!;
    const golfTrails = result.keyword.contributions.find((c) => c.term === "golf trails")!;
    expect(golfTrail.dedupedWith).toEqual(["golf trails"]);
    expect(golfTrails.dedupedWith).toEqual(["golf trail"]);
  });

  it("does NOT dedup a point value against another point value, even if numerically equal", () => {
    const log = buildLog("prop-1", [1000, 1000, 1000], {
      "golf trail": { pointValue: 500 },
      "golf trails": { pointValue: 500 },
      "robert trent jones golf trail": { pointValue: 500 },
      "tennessee golf trail": { pointValue: 500 },
      "vancouver island golf trail": { pointValue: 500 },
      "oklahoma golf trail": { pointValue: 500 },
    });
    const result = computeK3Verdict(log);
    expect(result.keyword.combinedVolume).toBe(3000); // 500 * 6, no dedup for points
  });
});

describe("computeK3Verdict: combined branch and consequence text", () => {
  it("both miss", () => {
    const log = buildLog("prop-1", [100, 150, 200], allPointValues(100));
    const result = computeK3Verdict(log);
    expect(result.searchConsole.pass).toBe(false);
    expect(result.keyword.pass).toBe(false);
    expect(result.combinedBranch).toBe("both-miss");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_BOTH_MISS);
  });

  it("disagree — search console passes, keyword misses", () => {
    const log = buildLog("prop-1", [1200, 1100, 1300], allPointValues(100));
    const result = computeK3Verdict(log);
    expect(result.searchConsole.pass).toBe(true);
    expect(result.keyword.pass).toBe(false);
    expect(result.combinedBranch).toBe("disagree");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_DISAGREE);
  });

  it("disagree — keyword passes, search console misses", () => {
    const log = buildLog("prop-1", [100, 100, 100], allPointValues(1000));
    const result = computeK3Verdict(log);
    expect(result.searchConsole.pass).toBe(false);
    expect(result.keyword.pass).toBe(true);
    expect(result.combinedBranch).toBe("disagree");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_DISAGREE);
  });

  it("both pass", () => {
    const log = buildLog("prop-1", [1000, 1100, 1200], {
      "golf trail": { lowerBound: 3000, upperBound: 4000 },
      "golf trails": { lowerBound: 3000, upperBound: 4000 }, // dedup -> 3000 once
      "robert trent jones golf trail": { pointValue: 500 },
      "tennessee golf trail": { pointValue: 500 },
      "vancouver island golf trail": { pointValue: 500 },
      "oklahoma golf trail": { pointValue: 500 },
    });
    const result = computeK3Verdict(log);
    expect(result.keyword.combinedVolume).toBe(5000); // 3000 + 4*500, exactly the bar
    expect(result.keyword.bar).toBe(K3_KEYWORD_BAR);
    expect(result.searchConsole.pass).toBe(true);
    expect(result.keyword.pass).toBe(true);
    expect(result.combinedBranch).toBe("both-pass");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_UNIVERSAL);
  });
});
