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

const VALID_PROPERTY_ID = "sc-domain:southernwinecountry.com";
const VALID_READ_DATE = "2026-10-05";
// Comfortably after VALID_READ_DATE and K3_MIN_READ_DATE.
const TODAY = "2026-12-01";

function scRows(clicks: [number | null, number | null, number | null]) {
  return K3_SEARCH_CONSOLE_MONTHS.map((month, i) => ({ month, clicks: clicks[i]! }));
}

function kwRows(
  values: Record<string, { lowerBound?: number | null; upperBound?: number | null }>,
): K3KeywordRow[] {
  return K3_KEYWORD_TERMS.map((term) => {
    const v = values[term] ?? {};
    return {
      term,
      lowerBound: v.lowerBound ?? null,
      upperBound: v.upperBound ?? null,
    };
  });
}

function allEqualBounds(value: number): Record<string, { lowerBound: number; upperBound: number }> {
  const out: Record<string, { lowerBound: number; upperBound: number }> = {};
  for (const t of K3_KEYWORD_TERMS) out[t] = { lowerBound: value, upperBound: value };
  return out;
}

function buildLog(
  opts: Partial<{
    propertyId: string;
    readDate: string | null;
    clicks: [number | null, number | null, number | null];
    keywords: Record<string, { lowerBound?: number | null; upperBound?: number | null }>;
  }>,
): K3Log {
  const {
    propertyId = VALID_PROPERTY_ID,
    readDate = VALID_READ_DATE,
    clicks = [1000, 1000, 1000],
    keywords = allEqualBounds(1000),
  } = opts;
  return { propertyId, readDate, searchConsole: scRows(clicks), keywords: kwRows(keywords) };
}

// `today` defaults to TODAY (comfortably after any readDate these tests
// use); tests about the read-date-vs-today relationship pass it explicitly.
function verdict(log: K3Log, today: string = TODAY): ReturnType<typeof computeK3Verdict> {
  return computeK3Verdict(log, today);
}

describe("computeK3Verdict: refusals", () => {
  it("refuses (throws) when the property id is blank", () => {
    expect(() => verdict(buildLog({ propertyId: "" }))).toThrow(/property id/);
  });

  it("refuses when the property id doesn't look like a real property (e.g. 'TBD')", () => {
    expect(() => verdict(buildLog({ propertyId: "TBD" }))).toThrow(/doesn't look like a Search Console/);
  });

  it("accepts an https:// URL-prefix property id", () => {
    const result = verdict(buildLog({ propertyId: "https://www.southernwinecountry.com/" }));
    expect(result.propertyId).toBe("https://www.southernwinecountry.com/");
  });

  it("accepts an http:// URL-prefix property id", () => {
    const result = verdict(buildLog({ propertyId: "http://www.southernwinecountry.com/" }));
    expect(result.propertyId).toBe("http://www.southernwinecountry.com/");
  });

  it("refuses when the read date is blank", () => {
    expect(() => verdict(buildLog({ readDate: null }))).toThrow(/read date/);
  });

  it("refuses when the read date is before 2026-10-01 (e.g. 2026-09-30)", () => {
    expect(() => verdict(buildLog({ readDate: "2026-09-30" }), "2026-12-01")).toThrow(/before 2026-10-01/);
  });

  it("refuses when the read date is not a real calendar date", () => {
    expect(() => verdict(buildLog({ readDate: "2026-13-45" }))).toThrow(/not a real calendar date/);
  });

  it("refuses when the read date is later than today", () => {
    expect(() => verdict(buildLog({ readDate: "2026-10-05" }), "2026-10-01")).toThrow(/later than today/);
  });

  it("refuses when a month's clicks total is blank", () => {
    expect(() => verdict(buildLog({ clicks: [1000, null, 1000] }))).toThrow(/missing: 2026-08/);
  });

  it("refuses when a keyword term has no range recorded", () => {
    const keywords = allEqualBounds(1000);
    delete (keywords as Record<string, unknown>)["golf trail"];
    expect(() => verdict(buildLog({ keywords }))).toThrow(/missing: golf trail/);
  });
});

describe("computeK3Verdict: Search Console median (decision 0001 Addendum A)", () => {
  it("takes the median of the three months regardless of input order", () => {
    // July=2000, August=500, September=1000 -> sorted [500, 1000, 2000] -> median 1000
    const result = verdict(buildLog({ clicks: [2000, 500, 1000] }));
    expect(result.searchConsole.median).toBe(1000);
    expect(result.searchConsole.bar).toBe(K3_SEARCH_CONSOLE_BAR);
    expect(result.searchConsole.pass).toBe(true); // 1000 >= 1000 bar (boundary)
  });

  it("just under the bar fails", () => {
    const result = verdict(buildLog({ clicks: [999, 999, 999] }));
    expect(result.searchConsole.pass).toBe(false);
  });
});

describe("computeK3Verdict: Keyword Planner — decision 0001 Addendum D R5 duplicate-range rule (Addendum I: applies to points too)", () => {
  it("counts an identical range shared by two terms only once", () => {
    const result = verdict(
      buildLog({
        keywords: {
          "golf trail": { lowerBound: 1000, upperBound: 1500 },
          "golf trails": { lowerBound: 1000, upperBound: 1500 }, // identical range -> dedup
          // The other 4 terms are each given a DISTINCT range so they
          // contribute individually (an equal range here would also dedup).
          "robert trent jones golf trail": { lowerBound: 100, upperBound: 100 },
          "tennessee golf trail": { lowerBound: 200, upperBound: 200 },
          "vancouver island golf trail": { lowerBound: 300, upperBound: 300 },
          "oklahoma golf trail": { lowerBound: 400, upperBound: 400 },
        },
      }),
    );
    // 1000 (once, not 2000) + 100 + 200 + 300 + 400 = 2000
    expect(result.keyword.combinedVolume).toBe(2000);
    const golfTrail = result.keyword.contributions.find((c) => c.term === "golf trail")!;
    const golfTrails = result.keyword.contributions.find((c) => c.term === "golf trails")!;
    expect(golfTrail.dedupedWith).toEqual(["golf trails"]);
    expect(golfTrails.dedupedWith).toEqual(["golf trail"]);
  });

  it("dedups an identical POINT value (lower === upper) shared by two terms, per Addendum I", () => {
    const result = verdict(
      buildLog({
        keywords: {
          "golf trail": { lowerBound: 500, upperBound: 500 },
          "golf trails": { lowerBound: 500, upperBound: 500 }, // identical point -> dedup
          "robert trent jones golf trail": { lowerBound: 500, upperBound: 500 },
          "tennessee golf trail": { lowerBound: 600, upperBound: 600 },
          "vancouver island golf trail": { lowerBound: 600, upperBound: 600 },
          "oklahoma golf trail": { lowerBound: 700, upperBound: 700 },
        },
      }),
    );
    // golf trail/golf trails/RTJ share 500 -> counted once; TN/VI share 600 -> once; OK 700 alone
    expect(result.keyword.combinedVolume).toBe(500 + 600 + 700);
  });
});

describe("computeK3Verdict: keyword sum boundary (bar >= 5000)", () => {
  it("a combined sum of 4,999 misses", () => {
    const result = verdict(
      buildLog({
        keywords: {
          "golf trail": { lowerBound: 4999, upperBound: 4999 },
          "golf trails": { lowerBound: 0, upperBound: 0 },
          "robert trent jones golf trail": { lowerBound: 0, upperBound: 0 },
          "tennessee golf trail": { lowerBound: 0, upperBound: 0 },
          "vancouver island golf trail": { lowerBound: 0, upperBound: 0 },
          "oklahoma golf trail": { lowerBound: 0, upperBound: 0 },
        },
      }),
    );
    expect(result.keyword.combinedVolume).toBe(4999);
    expect(result.keyword.pass).toBe(false);
  });

  it("a combined sum of 5,000 passes", () => {
    const result = verdict(
      buildLog({
        keywords: {
          "golf trail": { lowerBound: 5000, upperBound: 5000 },
          "golf trails": { lowerBound: 0, upperBound: 0 },
          "robert trent jones golf trail": { lowerBound: 0, upperBound: 0 },
          "tennessee golf trail": { lowerBound: 0, upperBound: 0 },
          "vancouver island golf trail": { lowerBound: 0, upperBound: 0 },
          "oklahoma golf trail": { lowerBound: 0, upperBound: 0 },
        },
      }),
    );
    expect(result.keyword.combinedVolume).toBe(5000);
    expect(result.keyword.bar).toBe(K3_KEYWORD_BAR);
    expect(result.keyword.pass).toBe(true);
  });
});

describe("computeK3Verdict: combined branch and consequence text", () => {
  it("both miss", () => {
    const result = verdict(buildLog({ clicks: [100, 150, 200], keywords: allEqualBounds(100) }));
    expect(result.searchConsole.pass).toBe(false);
    expect(result.keyword.pass).toBe(false);
    expect(result.combinedBranch).toBe("both-miss");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_BOTH_MISS);
  });

  it("disagree — search console passes, keyword misses", () => {
    const result = verdict(buildLog({ clicks: [1200, 1100, 1300], keywords: allEqualBounds(100) }));
    expect(result.searchConsole.pass).toBe(true);
    expect(result.keyword.pass).toBe(false);
    expect(result.combinedBranch).toBe("disagree");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_DISAGREE);
  });

  it("disagree — keyword passes, search console misses", () => {
    // Distinct point values (not allEqualBounds) so R5's dedup doesn't
    // collapse all six into a single ~1000 contribution.
    const keywords: Record<string, { lowerBound: number; upperBound: number }> = {};
    K3_KEYWORD_TERMS.forEach((t, i) => {
      keywords[t] = { lowerBound: 1000 + i, upperBound: 1000 + i };
    });
    const result = verdict(buildLog({ clicks: [100, 100, 100], keywords }));
    expect(result.searchConsole.pass).toBe(false);
    expect(result.keyword.pass).toBe(true);
    expect(result.combinedBranch).toBe("disagree");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_DISAGREE);
  });

  it("both pass", () => {
    const result = verdict(
      buildLog({
        clicks: [1000, 1100, 1200],
        keywords: {
          "golf trail": { lowerBound: 3000, upperBound: 4000 },
          "golf trails": { lowerBound: 3000, upperBound: 4000 }, // dedup -> 3000 once
          // 4 DISTINCT point values (equal ones would dedup too) summing to 2000.
          "robert trent jones golf trail": { lowerBound: 500, upperBound: 500 },
          "tennessee golf trail": { lowerBound: 600, upperBound: 600 },
          "vancouver island golf trail": { lowerBound: 470, upperBound: 470 },
          "oklahoma golf trail": { lowerBound: 430, upperBound: 430 },
        },
      }),
    );
    expect(result.keyword.combinedVolume).toBe(5000); // 3000 + (500+600+470+430), exactly the bar
    expect(result.searchConsole.pass).toBe(true);
    expect(result.keyword.pass).toBe(true);
    expect(result.combinedBranch).toBe("both-pass");
    expect(result.consequenceText).toBe(K3_CONSEQUENCE_UNIVERSAL);
  });
});
