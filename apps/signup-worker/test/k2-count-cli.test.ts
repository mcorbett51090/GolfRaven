import { describe, expect, it } from "vitest";
import { extractRows, parseDay0FromK2Doc, parseExcludedAddressesFromK2Doc } from "../scripts/k2-count.mjs";

describe("k2-count.mjs markdown parsing (mirrors docs/p0/K2.md's shape)", () => {
  it("returns null day0 for the still-blank placeholder section", () => {
    const markdown = `## Day 0

_(blank — Matt sets this ...)_

## Excluded addresses

_(blank — ...)_
`;
    expect(parseDay0FromK2Doc(markdown)).toBeNull();
  });

  it("parses a real ISO date once the owner fills it in", () => {
    const markdown = `## Day 0

2026-10-05

## Excluded addresses

_(blank)_
`;
    expect(parseDay0FromK2Doc(markdown)).toBe("2026-10-05");
  });

  it("parses an ISO datetime with a Z suffix", () => {
    const markdown = `## Day 0

Day 0 is 2026-10-05T00:00:00Z (UTC), logged before promotion.

## Excluded addresses
`;
    expect(parseDay0FromK2Doc(markdown)).toBe("2026-10-05T00:00:00Z");
  });

  it("parses zero excluded addresses from the blank placeholder", () => {
    const markdown = `## Excluded addresses

_(blank — any owner/test email addresses to exclude ...)_

## OWNER
`;
    expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([]);
  });

  it("parses one or more real addresses once the owner lists them", () => {
    const markdown = `## Excluded addresses

- matt@golfraven.example
- test+k2@golfraven.example

## OWNER
`;
    expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([
      "matt@golfraven.example",
      "test+k2@golfraven.example",
    ]);
  });
});

describe("extractRows", () => {
  it("accepts a plain row array", () => {
    const rows = [{ email_lc: "a@example.com", confirmed_at: "2026-10-06T00:00:00.000Z" }];
    expect(extractRows(rows)).toBe(rows);
  });

  it("unwraps a `wrangler d1 execute --json` result array", () => {
    const wranglerShape = [
      {
        results: [{ email_lc: "a@example.com", confirmed_at: "2026-10-06T00:00:00.000Z" }],
        success: true,
        meta: {},
      },
    ];
    expect(extractRows(wranglerShape)).toEqual(wranglerShape[0]!.results);
  });

  it("throws on an unrecognized shape", () => {
    expect(() => extractRows({ not: "an array" })).toThrow();
  });
});
