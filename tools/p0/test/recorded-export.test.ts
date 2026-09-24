import { describe, expect, it } from "vitest";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertExportDateMatches,
  assertRecordedExportDateLogged,
  bindExportHash,
  extractCalendarDate,
  informationalBanner,
  parseRecordedExportDates,
  type RecordedExportDates,
} from "../src/recorded-export.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const x1RealMarkdown = readFileSync(
  path.join(__dirname, "..", "..", "..", "docs", "p0", "X1.md"),
  "utf8",
);

const BLANK: RecordedExportDates = {
  ios: { date: null, sha256: null },
  android: { date: null, sha256: null },
};

describe("parseRecordedExportDates (decision 0005)", () => {
  it("parses both blank lines as null", () => {
    const markdown = `## Recorded export\n\n- iOS: \n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual(BLANK);
  });

  it("parses a logged iOS date, blank Android", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20\n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: null },
      android: { date: null, sha256: null },
    });
  });

  it("parses both dates logged", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20\n- Android: 2026-09-21\n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: null },
      android: { date: "2026-09-21", sha256: null },
    });
  });

  it("parses a date with a bound sha256", () => {
    const hash = "a".repeat(64);
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20 sha256:${hash}\n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: hash },
      android: { date: null, sha256: null },
    });
  });

  it("is case-insensitive on the OS label", () => {
    const markdown = `## Recorded export\n\n- ios: 2026-09-20\n- android: 2026-09-21\n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: null },
      android: { date: "2026-09-21", sha256: null },
    });
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

  it("throws on a malformed hash suffix (too short / uppercase)", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20 sha256:ABCD\n- Android: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/malformed value/);
  });

  it("the REAL docs/p0/X1.md parses without throwing and is still blank pre-round", () => {
    expect(parseRecordedExportDates(x1RealMarkdown)).toEqual(BLANK);
  });
});

describe("assertRecordedExportDateLogged", () => {
  it("throws for an OS with a blank date", () => {
    expect(() => assertRecordedExportDateLogged(BLANK, "ios")).toThrow(/iOS/);
    expect(() => assertRecordedExportDateLogged(BLANK, "android")).toThrow(/Android/);
  });

  it("does not throw for an OS with a logged date", () => {
    const dates: RecordedExportDates = { ios: { date: "2026-09-20", sha256: null }, android: { date: null, sha256: null } };
    expect(() => assertRecordedExportDateLogged(dates, "ios")).not.toThrow();
  });
});

describe("extractCalendarDate", () => {
  it("extracts YYYY-MM-DD from an Apple-style ExportDate string", () => {
    expect(extractCalendarDate("2026-09-21 09:00:00 -0400")).toBe("2026-09-21");
  });

  it("extracts YYYY-MM-DD from an ISO generatedAt string", () => {
    expect(extractCalendarDate("2026-09-21T13:00:00Z")).toBe("2026-09-21");
  });

  it("throws on an unparseable string", () => {
    expect(() => extractCalendarDate("not-a-date")).toThrow();
  });
});

describe("assertExportDateMatches", () => {
  it("throws on a mismatch", () => {
    const dates: RecordedExportDates = { ios: { date: "2026-09-20", sha256: null }, android: { date: null, sha256: null } };
    expect(() => assertExportDateMatches(dates, "ios", "2026-09-21")).toThrow(/does not match/);
  });

  it("does not throw when the calendar dates match", () => {
    const dates: RecordedExportDates = { ios: { date: "2026-09-20", sha256: null }, android: { date: null, sha256: null } };
    expect(() => assertExportDateMatches(dates, "ios", "2026-09-20")).not.toThrow();
  });
});

describe("bindExportHash", () => {
  function tmpX1Doc(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "golfraven-recorded-export-"));
    const file = path.join(dir, "X1.md");
    writeFileSync(
      file,
      "# X1\n\n## Recorded export\n\n- iOS: 2026-09-20\n- Android: \n\n## METHOD\n",
      "utf8",
    );
    return file;
  }

  it("writes the hash on the first recorded run (sha256 previously null)", async () => {
    const docPath = tmpX1Doc();
    const dates: RecordedExportDates = { ios: { date: "2026-09-20", sha256: null }, android: { date: null, sha256: null } };
    const hash = "b".repeat(64);
    const result = await bindExportHash(docPath, dates, "ios", hash);
    expect(result.written).toBe(true);
    const updated = readFileSync(docPath, "utf8");
    expect(updated).toContain(`- iOS: 2026-09-20 sha256:${hash}`);
  });

  it("does not throw and reports written:false when the hash already matches", async () => {
    const docPath = tmpX1Doc();
    const hash = "c".repeat(64);
    const dates: RecordedExportDates = { ios: { date: "2026-09-20", sha256: hash }, android: { date: null, sha256: null } };
    const result = await bindExportHash(docPath, dates, "ios", hash);
    expect(result.written).toBe(false);
  });

  it("throws on a hash mismatch — a different export than the one first bound", async () => {
    const docPath = tmpX1Doc();
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "c".repeat(64) },
      android: { date: null, sha256: null },
    };
    await expect(bindExportHash(docPath, dates, "ios", "d".repeat(64))).rejects.toThrow(
      /does not match the hash already recorded/,
    );
  });
});

describe("informationalBanner", () => {
  it("names the OS and says NOT THE RECORDED X1 RESULT", () => {
    expect(informationalBanner("ios")).toContain("NOT THE RECORDED X1 RESULT");
    expect(informationalBanner("ios")).toContain("iOS");
    expect(informationalBanner("android")).toContain("Android");
  });
});
