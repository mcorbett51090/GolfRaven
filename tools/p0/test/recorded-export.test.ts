import { describe, expect, it } from "vitest";
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  assertExportDateMatches,
  assertGitIntegrity,
  assertHashHistoryIntact,
  assertNoInformationalPeeking,
  assertNotShallowClone,
  assertRecordedExportDateLogged,
  assertX1DocCommitted,
  bindExportHash,
  computeOverallX1Result,
  extractCalendarDate,
  informationalBanner,
  parseRecordedExportDates,
  readRecordedExportDates,
  writeRecordedResult,
  type RecordedExportDates,
} from "../src/recorded-export.js";

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const x1RealMarkdown = readFileSync(
  path.join(__dirname, "..", "..", "..", "docs", "p0", "X1.md"),
  "utf8",
);

const BLANK: RecordedExportDates = {
  ios: { date: null, sha256: null, result: null },
  android: { date: null, sha256: null, result: null },
};

describe("parseRecordedExportDates (decision 0005)", () => {
  it("parses both blank lines as null", () => {
    const markdown = `## Recorded export\n\n- iOS: \n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual(BLANK);
  });

  it("parses a logged iOS date, blank Android", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20\n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: null, result: null },
      android: { date: null, sha256: null, result: null },
    });
  });

  it("parses both dates logged", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20\n- Android: 2026-09-21\n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: null, result: null },
      android: { date: "2026-09-21", sha256: null, result: null },
    });
  });

  it("parses a date with a bound sha256", () => {
    const hash = "a".repeat(64);
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20 sha256:${hash}\n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: hash, result: null },
      android: { date: null, sha256: null, result: null },
    });
  });

  it("parses a date with a bound sha256 AND a recorded result", () => {
    const hash = "a".repeat(64);
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20 sha256:${hash} result:kill\n- Android: \n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: hash, result: "kill" },
      android: { date: null, sha256: null, result: null },
    });
  });

  it("is case-insensitive on the OS label", () => {
    const markdown = `## Recorded export\n\n- ios: 2026-09-20\n- android: 2026-09-21\n\n## METHOD\n`;
    expect(parseRecordedExportDates(markdown)).toEqual({
      ios: { date: "2026-09-20", sha256: null, result: null },
      android: { date: "2026-09-21", sha256: null, result: null },
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
    expect(() => parseRecordedExportDates(markdown)).toThrow(/malformed/);
  });

  it("throws on a malformed hash suffix (too short / uppercase)", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20 sha256:ABCD\n- Android: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/malformed value/);
  });

  it("throws on an invalid result value", () => {
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20 result:maybe\n- Android: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/malformed value/);
  });

  it("the REAL docs/p0/X1.md parses without throwing and is still blank pre-round", () => {
    expect(parseRecordedExportDates(x1RealMarkdown)).toEqual(BLANK);
  });
});

describe("assertRecordedExportDateLogged", () => {
  it("throws for an OS with a blank date", () => {
    expect(() => assertRecordedExportDateLogged(BLANK, "ios")).toThrow(/UTC date/);
    expect(() => assertRecordedExportDateLogged(BLANK, "android")).toThrow(/UTC date/);
  });

  it("does not throw for an OS with a logged date", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null, result: null },
      android: { date: null, sha256: null, result: null },
    };
    expect(() => assertRecordedExportDateLogged(dates, "ios")).not.toThrow();
  });
});

describe("assertNoInformationalPeeking (round-2 Opus-gate correction)", () => {
  it("throws when a date is logged but no hash is bound yet", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null, result: null },
      android: { date: null, sha256: null, result: null },
    };
    expect(() => assertNoInformationalPeeking(dates, "ios")).toThrow(/no informational peeking/i);
  });

  it("does not throw when no date is logged at all", () => {
    expect(() => assertNoInformationalPeeking(BLANK, "ios")).not.toThrow();
  });

  it("does not throw once the hash IS bound", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "a".repeat(64), result: null },
      android: { date: null, sha256: null, result: null },
    };
    expect(() => assertNoInformationalPeeking(dates, "ios")).not.toThrow();
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
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null, result: null },
      android: { date: null, sha256: null, result: null },
    };
    expect(() => assertExportDateMatches(dates, "ios", "2026-09-21")).toThrow(/does not match/);
  });

  it("does not throw when the calendar dates match", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null, result: null },
      android: { date: null, sha256: null, result: null },
    };
    expect(() => assertExportDateMatches(dates, "ios", "2026-09-20")).not.toThrow();
  });
});

function tmpX1Doc(body = "- iOS: 2026-09-20\n- Android: \n"): string {
  const dir = mkdtempSync(path.join(tmpdir(), "golfraven-recorded-export-"));
  const file = path.join(dir, "X1.md");
  writeFileSync(file, `# X1\n\n## Recorded export\n\n${body}\n## METHOD\n`, "utf8");
  return file;
}

describe("bindExportHash", () => {
  it("writes the hash on the first recorded run (sha256 previously null)", async () => {
    const docPath = tmpX1Doc();
    const hash = "b".repeat(64);
    const result = await bindExportHash(docPath, "ios", hash);
    expect(result.written).toBe(true);
    const updated = readFileSync(docPath, "utf8");
    expect(updated).toContain(`- iOS: 2026-09-20 sha256:${hash}`);
  });

  it("does not throw and reports written:false when the hash already matches", async () => {
    const hash = "c".repeat(64);
    const docPath = tmpX1Doc(`- iOS: 2026-09-20 sha256:${hash}\n- Android: \n`);
    const result = await bindExportHash(docPath, "ios", hash);
    expect(result.written).toBe(false);
  });

  it("throws on a hash mismatch — a different export than the one first bound", async () => {
    const docPath = tmpX1Doc(`- iOS: 2026-09-20 sha256:${"c".repeat(64)}\n- Android: \n`);
    await expect(bindExportHash(docPath, "ios", "d".repeat(64))).rejects.toThrow(
      /does not match the hash already recorded/,
    );
  });

  it("preserves an already-set result: suffix when binding the hash", async () => {
    const docPath = tmpX1Doc("- iOS: 2026-09-20 result:pass\n- Android: \n");
    await bindExportHash(docPath, "ios", "e".repeat(64));
    const updated = readFileSync(docPath, "utf8");
    expect(updated).toContain(`- iOS: 2026-09-20 sha256:${"e".repeat(64)} result:pass`);
  });
});

describe("writeRecordedResult", () => {
  it("writes the result on the first run (result previously null)", async () => {
    const docPath = tmpX1Doc(`- iOS: 2026-09-20 sha256:${"a".repeat(64)}\n- Android: \n`);
    const result = await writeRecordedResult(docPath, "ios", "kill");
    expect(result.written).toBe(true);
    const updated = readFileSync(docPath, "utf8");
    expect(updated).toContain(`- iOS: 2026-09-20 sha256:${"a".repeat(64)} result:kill`);
  });

  it("does not throw and reports written:false when the result already matches", async () => {
    const docPath = tmpX1Doc(`- iOS: 2026-09-20 sha256:${"a".repeat(64)} result:pass\n- Android: \n`);
    const result = await writeRecordedResult(docPath, "ios", "pass");
    expect(result.written).toBe(false);
  });

  it("throws when trying to silently change an already-recorded result", async () => {
    const docPath = tmpX1Doc(`- iOS: 2026-09-20 sha256:${"a".repeat(64)} result:pass\n- Android: \n`);
    await expect(writeRecordedResult(docPath, "ios", "kill")).rejects.toThrow(
      /already records.*refusing to silently change/is,
    );
  });
});

describe("computeOverallX1Result", () => {
  it("pending when neither OS has a recorded result", () => {
    expect(computeOverallX1Result(BLANK)).toBe("pending");
  });

  it("pending when only one OS has a recorded result", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "a".repeat(64), result: "kill" },
      android: { date: null, sha256: null, result: null },
    };
    expect(computeOverallX1Result(dates)).toBe("pending");
  });

  it("pass when either OS's recorded result is pass", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "a".repeat(64), result: "kill" },
      android: { date: "2026-09-21", sha256: "b".repeat(64), result: "pass" },
    };
    expect(computeOverallX1Result(dates)).toBe("pass");
  });

  it("kill when both OSes have recorded results and neither passed", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "a".repeat(64), result: "kill" },
      android: { date: "2026-09-21", sha256: "b".repeat(64), result: "kill" },
    };
    expect(computeOverallX1Result(dates)).toBe("kill");
  });
});

describe("cross-run combination — the actual mechanism behind 'an --os ios run with a hand-stamped Android pass does not make the overall result a pass'", () => {
  it("two SEPARATE runs (one per OS), each writing only its own result, combine correctly with NO shared call", async () => {
    const docPath = tmpX1Doc("- iOS: 2026-09-20 sha256:${aHash}\n- Android: 2026-09-21 sha256:${bHash}\n"
      .replace("${aHash}", "a".repeat(64))
      .replace("${bHash}", "b".repeat(64)));

    // "Run 1": an --os ios recorded run, knowing NOTHING about Android,
    // computes iOS's own verdict as kill and writes it.
    await writeRecordedResult(docPath, "ios", "kill");
    // Before Android's run happens, the overall is still "pending" — NOT
    // pass, even though nothing here claims Android passed yet.
    const { dates: afterIosOnly } = await readRecordedExportDates(docPath);
    expect(computeOverallX1Result(afterIosOnly)).toBe("pending");

    // "Run 2": a SEPARATE --os android recorded run (different process,
    // different invocation, no access to run 1's ios/android input data at
    // all) computes Android's own verdict as pass and writes it.
    await writeRecordedResult(docPath, "android", "pass");
    const { dates: afterBoth } = await readRecordedExportDates(docPath);
    expect(afterBoth.ios.result).toBe("kill");
    expect(afterBoth.android.result).toBe("pass");
    expect(computeOverallX1Result(afterBoth)).toBe("pass");
  });

  it("a hand-stamped 'recorded:true' claim on raw Android DATA (never durably written as a result:) never contributes — only writeRecordedResult's durable record does", async () => {
    // This is the library-level proof behind the CLI-level rule: nothing
    // about a JSON's own `recorded`/`os` claim ever reaches
    // docs/p0/X1.md — only an explicit `writeRecordedResult` call (which
    // main() only makes after independently verified git+hash binding)
    // does. A hand-stamped JSON with no such call behind it simply never
    // appears in `dates` at all.
    const docPath = tmpX1Doc(`- iOS: 2026-09-20 sha256:${"a".repeat(64)}\n- Android: \n`);
    await writeRecordedResult(docPath, "ios", "kill");
    const { dates } = await readRecordedExportDates(docPath);
    // Android has no logged date, let alone a result — "hand-stamping" the
    // INPUT JSON (which this module never even reads) changes nothing here.
    expect(dates.android.result).toBeNull();
    expect(computeOverallX1Result(dates)).toBe("pending");
  });
});

describe("informationalBanner", () => {
  it("names the OS and says NOT THE RECORDED X1 RESULT", () => {
    expect(informationalBanner("ios")).toContain("NOT THE RECORDED X1 RESULT");
    expect(informationalBanner("ios")).toContain("iOS");
    expect(informationalBanner("android")).toContain("Android");
  });
});

// ---------------------------------------------------------------------
// Git integrity (round-2 Opus-gate correction, should-fix 3) — a real
// temporary git repo fixture, per the task's explicit instruction to test
// hash-history tampering "in a temporary git repo fixture."
// ---------------------------------------------------------------------

async function initTmpGitRepo(): Promise<{ repoDir: string; x1DocPath: string }> {
  const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-x1-git-"));
  await execFileAsync("git", ["init", "-q"], { cwd: repoDir });
  await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: repoDir });
  await execFileAsync("git", ["config", "user.name", "Test"], { cwd: repoDir });
  const docsDir = path.join(repoDir, "docs", "p0");
  mkdirSync(docsDir, { recursive: true });
  const x1DocPath = path.join(docsDir, "X1.md");
  return { repoDir, x1DocPath };
}

async function commitFile(repoDir: string, x1DocPath: string, body: string, message: string): Promise<void> {
  writeFileSync(x1DocPath, `# X1\n\n## Recorded export\n\n${body}\n## METHOD\n`, "utf8");
  await execFileAsync("git", ["add", "-A"], { cwd: repoDir });
  await execFileAsync("git", ["commit", "-q", "-m", message], { cwd: repoDir });
}

describe("git integrity checks (round-2 Opus-gate correction, should-fix 3)", () => {
  it("assertX1DocCommitted does not throw when the file is committed and clean", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    await expect(assertX1DocCommitted(x1DocPath)).resolves.not.toThrow();
  });

  it("assertX1DocCommitted throws when the file has uncommitted changes", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    writeFileSync(
      x1DocPath,
      `# X1\n\n## Recorded export\n\n- iOS: 2026-09-20 sha256:${"a".repeat(64)}\n- Android: \n\n## METHOD\n`,
      "utf8",
    );
    await expect(assertX1DocCommitted(x1DocPath)).rejects.toThrow(/uncommitted changes/);
  });

  it("assertHashHistoryIntact does not throw when a hash has never been bound", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    await expect(assertHashHistoryIntact(x1DocPath, "ios")).resolves.not.toThrow();
  });

  it("assertHashHistoryIntact does not throw when the current hash matches history", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    const hash = "a".repeat(64);
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    await commitFile(repoDir, x1DocPath, `- iOS: 2026-09-20 sha256:${hash}\n- Android: \n`, "bind iOS hash");
    await expect(assertHashHistoryIntact(x1DocPath, "ios")).resolves.not.toThrow();
  });

  it("assertHashHistoryIntact throws when the bound hash was CHANGED in a later commit", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    const firstHash = "a".repeat(64);
    const secondHash = "b".repeat(64);
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    await commitFile(repoDir, x1DocPath, `- iOS: 2026-09-20 sha256:${firstHash}\n- Android: \n`, "bind iOS hash");
    await commitFile(
      repoDir,
      x1DocPath,
      `- iOS: 2026-09-20 sha256:${secondHash}\n- Android: \n`,
      "quietly swap the bound hash",
    );
    await expect(assertHashHistoryIntact(x1DocPath, "ios")).rejects.toThrow(/changed across git history/);
  });

  it("assertHashHistoryIntact throws when the bound hash was REMOVED in a later commit", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    const hash = "a".repeat(64);
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    await commitFile(repoDir, x1DocPath, `- iOS: 2026-09-20 sha256:${hash}\n- Android: \n`, "bind iOS hash");
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "quietly remove the bound hash");
    await expect(assertHashHistoryIntact(x1DocPath, "ios")).rejects.toThrow(/was previously set.*now blank/is);
  });

  it("assertNotShallowClone does not throw in a normal (non-shallow) repo", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    await expect(assertNotShallowClone(x1DocPath)).resolves.not.toThrow();
  });

  it("assertGitIntegrity runs all three checks and does not throw on a clean, intact repo", async () => {
    const { repoDir, x1DocPath } = await initTmpGitRepo();
    await commitFile(repoDir, x1DocPath, "- iOS: 2026-09-20\n- Android: \n", "log iOS date");
    await expect(assertGitIntegrity(x1DocPath, "ios")).resolves.not.toThrow();
  });
});
