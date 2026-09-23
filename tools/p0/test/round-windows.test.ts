import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseRoundWindows,
  isWithinRoundWindow,
} from "../src/round-windows.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const x1RealMarkdown = readFileSync(
  path.join(__dirname, "..", "..", "..", "docs", "p0", "X1.md"),
  "utf8",
);

describe("parseRoundWindows (decision 0001 Addendum F)", () => {
  it("returns [] for a blank placeholder section, even one that describes the ISO format in prose", () => {
    // Regression: the blank placeholder text must NOT itself contain a
    // literal <ISO> to <ISO> pattern the parser could mistake for a real
    // logged window.
    const markdown = `## Round windows

_(blank — Matt logs the UTC start/end time of each round here, format YYYY-MM-DDThh:mm:ssZ to
YYYY-MM-DDThh:mm:ssZ.)_

## METHOD
`;
    expect(parseRoundWindows(markdown)).toEqual([]);
  });

  it("parses a single logged window", () => {
    const markdown = `## Round windows

- 2026-09-20T13:00:00Z to 2026-09-20T18:30:00Z

## METHOD
`;
    expect(parseRoundWindows(markdown)).toEqual([
      { startIso: "2026-09-20T13:00:00Z", endIso: "2026-09-20T18:30:00Z" },
    ]);
  });

  it("parses more than one window (iOS round + Android round on different days)", () => {
    const markdown = `## Round windows

- 2026-09-20T13:00:00Z to 2026-09-20T18:30:00Z
- 2026-09-21T13:00:00Z to 2026-09-21T18:30:00Z

## METHOD
`;
    expect(parseRoundWindows(markdown)).toHaveLength(2);
  });

  it("throws when the '## Round windows' heading is missing entirely", () => {
    const markdown = `## METHOD\n\nSomething else.\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(/Round windows/);
  });

  it("the REAL docs/p0/X1.md parses without throwing and is still blank pre-round", () => {
    expect(parseRoundWindows(x1RealMarkdown)).toEqual([]);
  });
});

describe("parseRoundWindows: malformed windows are rejected, not silently swallowed (gate finding F-S6)", () => {
  it("throws on an invalid hour (> 23)", () => {
    const markdown = `## Round windows\n\n- 2026-09-20T13:00:00Z to 2026-09-20T25:30:00Z\n\n## METHOD\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(/malformed timestamp/);
  });

  it("throws on an invalid minute (> 59)", () => {
    const markdown = `## Round windows\n\n- 2026-09-20T13:60:00Z to 2026-09-20T17:00:00Z\n\n## METHOD\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(/malformed timestamp/);
  });

  it("throws on a non-existent calendar date (day 31 of a 30-day month)", () => {
    const markdown = `## Round windows\n\n- 2026-09-31T13:00:00Z to 2026-09-31T17:00:00Z\n\n## METHOD\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(
      /not a valid calendar date/,
    );
  });

  it("throws on a reversed window (start >= end)", () => {
    const markdown = `## Round windows\n\n- 2026-09-20T17:30:00Z to 2026-09-20T13:00:00Z\n\n## METHOD\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(/end > start/);
  });

  it("throws when start equals end", () => {
    const markdown = `## Round windows\n\n- 2026-09-20T13:00:00Z to 2026-09-20T13:00:00Z\n\n## METHOD\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(/end > start/);
  });

  it("throws on a window longer than 8 hours", () => {
    const markdown = `## Round windows\n\n- 2026-09-20T08:00:00Z to 2026-09-20T17:00:00Z\n\n## METHOD\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(/longer than 8 hours/);
  });

  it("throws on a non-UTC offset instead of Z", () => {
    const markdown = `## Round windows\n\n- 2026-09-20T13:00:00-04:00 to 2026-09-20T17:00:00-04:00\n\n## METHOD\n`;
    expect(() => parseRoundWindows(markdown)).toThrow(/malformed timestamp/);
  });

  it("never returns a window that would silently match nothing — every accepted window has end > start and <= 8h", () => {
    const markdown = `## Round windows\n\n- 2026-09-20T13:00:00Z to 2026-09-20T17:30:00Z\n\n## METHOD\n`;
    const windows = parseRoundWindows(markdown);
    expect(windows).toHaveLength(1);
    expect(Date.parse(windows[0]!.endIso)).toBeGreaterThan(
      Date.parse(windows[0]!.startIso),
    );
  });
});

describe("isWithinRoundWindow", () => {
  const windows = [
    { startIso: "2026-09-20T13:00:00Z", endIso: "2026-09-20T18:00:00Z" },
  ];

  it("true for a start time inside the window", () => {
    expect(isWithinRoundWindow("2026-09-20T15:00:00Z", windows)).toBe(true);
  });

  it("true within the 60-minute slack before/after the window", () => {
    expect(isWithinRoundWindow("2026-09-20T12:01:00Z", windows)).toBe(true);
    expect(isWithinRoundWindow("2026-09-20T18:59:00Z", windows)).toBe(true);
  });

  it("false outside the slack", () => {
    expect(isWithinRoundWindow("2026-09-20T11:59:00Z", windows)).toBe(false);
    expect(isWithinRoundWindow("2026-09-20T19:01:00Z", windows)).toBe(false);
  });

  it("false for null or unparseable start times", () => {
    expect(isWithinRoundWindow(null, windows)).toBe(false);
    expect(isWithinRoundWindow("not-a-date", windows)).toBe(false);
  });
});
