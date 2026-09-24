import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertRecordedExportDateLogged,
  informationalBanner,
  parseRecordedExportDates,
} from "../src/recorded-export.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const x1RealMarkdown = readFileSync(
  path.join(__dirname, "..", "..", "..", "docs", "p0", "X1.md"),
  "utf8",
);

describe("parseRecordedExportDates (decision 0005)", () => {
  it("parses both blank lines as null", () => {
    const markdown = `## Recorded export\n\n- iOS: \n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({ ios: null, android: null });
  });

  it("parses a logged iOS date, blank Android", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20\n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({ ios: "2026-09-20", android: null });
  });

  it("parses both dates logged", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20\n- Android: 2026-09-21\n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({ ios: "2026-09-20", android: "2026-09-21" });
  });

  it("is case-insensitive on the OS label", () => {
    const markdown = `## Recorded export\n\n- ios: 2026-09-20\n- android: 2026-09-21\n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({ ios: "2026-09-20", android: "2026-09-21" });
  });

  it("throws when the heading is missing", () => {
    const markdown = `## METHOD\n\nSomething else.\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/Recorded export/);
  });

  it("throws when the iOS line is missing", () => {
    const markdown = `## Recorded export\n\n- Android: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/iOS/);
  });

  it("throws when the Android line is missing", () => {
    const markdown = `## Recorded export\n\n- iOS: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/Android/);
  });

  it("throws when an OS line appears twice", () => {
    const markdown = `## Recorded export\n\n- iOS: \n- iOS: 2026-09-20\n- Android: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/more than one/);
  });

  it("throws on a malformed date", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-13-45\n- Android: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/malformed date/);
  });

  it("the REAL docs/p0/X1.md parses without throwing and is still blank pre-round", () => {
    expect(parseRecordedExportDates(x1RealMarkdown)).toEqual({ ios: null, android: null });
  });
});

describe("assertRecordedExportDateLogged", () => {
  it("throws for an OS with a blank date", () => {
    expect(() => assertRecordedExportDateLogged({ ios: null, android: null }, "ios")).toThrow(/iOS/);
    expect(() => assertRecordedExportDateLogged({ ios: null, android: null }, "android")).toThrow(/Android/);
  });

  it("does not throw for an OS with a logged date", () => {
    expect(() =>
      assertRecordedExportDateLogged({ ios: "2026-09-20", android: null }, "ios"),
    ).not.toThrow();
  });
});

describe("informationalBanner", () => {
  it("names the OS and says NOT THE RECORDED X1 RESULT", () => {
    expect(informationalBanner("ios")).toContain("NOT THE RECORDED X1 RESULT");
    expect(informationalBanner("ios")).toContain("iOS");
    expect(informationalBanner("android")).toContain("Android");
  });
});
