import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertBoundInputProvided,
  assertDocCommitted,
  assertExportDateMatches,
  assertInformationalInputAllowed,
  assertRecordedExportDateLogged,
  bindExportHash,
  extractCalendarDate,
  informationalBanner,
  isUnderFixturesDir,
  parseRecordedExportDates,
  resolveFixturesDir,
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

  it("round-3: no longer accepts a result: suffix — it's a malformed value now", () => {
    const hash = "a".repeat(64);
    const markdown = `## Recorded export\n\n- iOS: 2026-09-20 sha256:${hash} result:kill\n- Android: \n\n## METHOD\n`;
    expect(() => parseRecordedExportDates(markdown)).toThrow(/malformed value/);
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
    expect(() => parseRecordedExportDates(markdown)).toThrow(/malformed/);
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
    expect(() => assertRecordedExportDateLogged(BLANK, "ios")).toThrow(/UTC date/);
    expect(() => assertRecordedExportDateLogged(BLANK, "android")).toThrow(/UTC date/);
  });

  it("does not throw for an OS with a logged date", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null },
      android: { date: null, sha256: null },
    };
    expect(() => assertRecordedExportDateLogged(dates, "ios")).not.toThrow();
  });
});

describe("resolveFixturesDir / isUnderFixturesDir", () => {
  it("resolves to a real tools/p0/test/fixtures directory", () => {
    const dir = resolveFixturesDir();
    expect(dir.endsWith(path.join("test", "fixtures"))).toBe(true);
  });

  it("recognizes a path under fixtures", () => {
    const dir = resolveFixturesDir();
    expect(isUnderFixturesDir(path.join(dir, "some-export"))).toBe(true);
    expect(isUnderFixturesDir(dir)).toBe(true);
  });

  it("rejects a path outside fixtures", () => {
    expect(isUnderFixturesDir("/tmp/some-real-export")).toBe(false);
    expect(isUnderFixturesDir(path.join(tmpdir(), "not-fixtures"))).toBe(false);
  });

  it("round-4 Opus-gate correction (post-4279773, nit): does NOT treat a symlink placed UNDER fixtures as 'under fixtures' when it points OUTSIDE it", () => {
    const dir = resolveFixturesDir();
    const outsideTarget = mkdtempSync(path.join(tmpdir(), "golfraven-outside-fixtures-"));
    const linkPath = path.join(dir, "escape-symlink-test");
    try {
      symlinkSync(outsideTarget, linkPath, "dir");
      // Syntactically the link's own path IS under fixtures/ — the point
      // of following it with realpath is that it must not read as such.
      expect(isUnderFixturesDir(linkPath)).toBe(false);
    } finally {
      rmSync(linkPath, { force: true });
      rmSync(outsideTarget, { recursive: true, force: true });
    }
  });
});

describe("assertInformationalInputAllowed (round-3 Opus-gate correction, post-8e5a29b)", () => {
  const fixturesPath = path.join(resolveFixturesDir(), "export-dir");

  it("throws for real (non-fixture) data while the OS has no bound date at all", () => {
    expect(() => assertInformationalInputAllowed(BLANK, "ios", "/tmp/real-export")).toThrow(
      /no informational runs on real data/i,
    );
  });

  it("throws for real (non-fixture) data while the OS has a logged date but no bound hash", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null },
      android: { date: null, sha256: null },
    };
    expect(() => assertInformationalInputAllowed(dates, "ios", "/tmp/real-export")).toThrow(
      /no informational runs on real data/i,
    );
  });

  it("does NOT throw for a fixture path, regardless of bound state", () => {
    expect(() => assertInformationalInputAllowed(BLANK, "ios", fixturesPath)).not.toThrow();
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null },
      android: { date: null, sha256: null },
    };
    expect(() => assertInformationalInputAllowed(dates, "ios", fixturesPath)).not.toThrow();
  });

  it("does NOT throw for real data once the OS IS bound", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "a".repeat(64) },
      android: { date: null, sha256: null },
    };
    expect(() => assertInformationalInputAllowed(dates, "ios", "/tmp/real-export")).not.toThrow();
  });

  it("round-4 Opus-gate correction (post-4279773, nit): refuses through a symlink placed UNDER fixtures that points OUTSIDE it, while unbound", () => {
    const dir = resolveFixturesDir();
    const outsideTarget = mkdtempSync(path.join(tmpdir(), "golfraven-outside-fixtures-"));
    const linkPath = path.join(dir, "escape-symlink-test-informational");
    try {
      symlinkSync(outsideTarget, linkPath, "dir");
      expect(() => assertInformationalInputAllowed(BLANK, "ios", linkPath)).toThrow(
        /no informational runs on real data/i,
      );
    } finally {
      rmSync(linkPath, { force: true });
      rmSync(outsideTarget, { recursive: true, force: true });
    }
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
      ios: { date: "2026-09-20", sha256: null },
      android: { date: null, sha256: null },
    };
    expect(() => assertExportDateMatches(dates, "ios", "2026-09-21")).toThrow(/does not match/);
  });

  it("does not throw when the calendar dates match", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null },
      android: { date: null, sha256: null },
    };
    expect(() => assertExportDateMatches(dates, "ios", "2026-09-20")).not.toThrow();
  });
});

const GIT_TEST_IDENTITY = ["-c", "user.name=Test", "-c", "user.email=test@example.com"];

/** Runs `git <args>` in `cwd` synchronously (tests only — the src side is
 * always async via `execFileAsync`), with a pinned test identity so these
 * tests never depend on the host having a global git identity configured. */
function git(cwd: string, args: string[]): string {
  return execFileSync("git", [...GIT_TEST_IDENTITY, ...args], { cwd, encoding: "utf8" });
}

/** A fresh temp directory that IS a git repo, with `X1.md` written and
 * committed — the round-4 baseline every `bindExportHash`/`assertDocCommitted`
 * test needs now that both require a real git repository. */
function tmpGitX1Doc(body = "- iOS: 2026-09-20\n- Android: \n"): string {
  const dir = mkdtempSync(path.join(tmpdir(), "golfraven-recorded-export-git-"));
  git(dir, ["init", "-q"]);
  const file = path.join(dir, "X1.md");
  writeFileSync(file, `# X1\n\n## Recorded export\n\n${body}\n## METHOD\n`, "utf8");
  git(dir, ["add", "X1.md"]);
  git(dir, ["commit", "-q", "-m", "init"]);
  return file;
}

describe("bindExportHash", () => {
  it("writes the hash on the first recorded run (sha256 previously null)", async () => {
    const docPath = tmpGitX1Doc();
    const hash = "b".repeat(64);
    const result = await bindExportHash(docPath, "ios", hash);
    expect(result.written).toBe(true);
    const updated = readFileSync(docPath, "utf8");
    expect(updated).toContain(`- iOS: 2026-09-20 sha256:${hash}`);
  });

  it("does not throw and reports written:false when the hash already matches", async () => {
    const hash = "c".repeat(64);
    const docPath = tmpGitX1Doc(`- iOS: 2026-09-20 sha256:${hash}\n- Android: \n`);
    const result = await bindExportHash(docPath, "ios", hash);
    expect(result.written).toBe(false);
  });

  it("throws on a hash mismatch — a different export than the one first bound", async () => {
    const docPath = tmpGitX1Doc(`- iOS: 2026-09-20 sha256:${"c".repeat(64)}\n- Android: \n`);
    await expect(bindExportHash(docPath, "ios", "d".repeat(64))).rejects.toThrow(
      /does not match the hash already recorded/,
    );
  });

  it("throws when docs/p0/X1.md isn't inside a git repository at all", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "golfraven-recorded-export-nogit-"));
    const file = path.join(dir, "X1.md");
    writeFileSync(file, "# X1\n\n## Recorded export\n\n- iOS: 2026-09-20\n- Android: \n\n## METHOD\n", "utf8");
    await expect(bindExportHash(file, "ios", "e".repeat(64))).rejects.toThrow(
      /not a real git repository|git .* failed/i,
    );
  });
});

describe("re-binding after a delete/revert is refused (round-4 Opus-gate correction, post-4279773)", () => {
  it("refuses a second bind once git history shows iOS was bound before, even though the hash line now reads as unbound", async () => {
    const docPath = tmpGitX1Doc();
    const firstHash = "1".repeat(64);
    // First bind: succeeds, and is committed (the real workflow's "commit
    // and push docs/p0/X1.md now" step).
    const first = await bindExportHash(docPath, "ios", firstHash);
    expect(first.written).toBe(true);
    git(path.dirname(docPath), ["add", "X1.md"]);
    git(path.dirname(docPath), ["commit", "-q", "-m", "bind iOS"]);

    // Delete (revert) the sha256: suffix — back to just a bare logged date
    // — and commit THAT too, so the line now reads as unbound again.
    writeFileSync(docPath, "# X1\n\n## Recorded export\n\n- iOS: 2026-09-20\n- Android: \n\n## METHOD\n", "utf8");
    git(path.dirname(docPath), ["add", "X1.md"]);
    git(path.dirname(docPath), ["commit", "-q", "-m", "revert iOS bind"]);

    // A second bind — even to the SAME export's hash, let alone a
    // different one — must be refused: only an owner decision reopens it.
    await expect(bindExportHash(docPath, "ios", "2".repeat(64))).rejects.toThrow(
      /re-binding needs an owner decision/,
    );
  });

  it("does NOT refuse a genuinely first-ever bind (no prior sha256: anywhere in history)", async () => {
    const docPath = tmpGitX1Doc();
    const result = await bindExportHash(docPath, "ios", "3".repeat(64));
    expect(result.written).toBe(true);
  });
});

describe("assertDocCommitted (round-4 Opus-gate correction, post-4279773) — 'verdicts come only from a committed binding'", () => {
  it("does not throw when docs/p0/X1.md has no uncommitted changes", async () => {
    const docPath = tmpGitX1Doc();
    await expect(assertDocCommitted(docPath)).resolves.toBeUndefined();
  });

  it("throws when docs/p0/X1.md has uncommitted changes", async () => {
    const docPath = tmpGitX1Doc();
    writeFileSync(docPath, "# X1\n\n## Recorded export\n\n- iOS: 2026-09-21\n- Android: \n\n## METHOD\n", "utf8");
    await expect(assertDocCommitted(docPath)).rejects.toThrow(/uncommitted changes/);
  });

  it("throws when docs/p0/X1.md is not inside a git repository at all", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "golfraven-recorded-export-nogit-"));
    const file = path.join(dir, "X1.md");
    writeFileSync(file, "# X1\n\n## Recorded export\n\n- iOS: \n- Android: \n\n## METHOD\n", "utf8");
    await expect(assertDocCommitted(file)).rejects.toThrow(/git .* failed|not a git repository/i);
  });
});

describe("assertBoundInputProvided (round-3 Opus-gate correction, post-8e5a29b) — 'a missing bound OS input is refused'", () => {
  it("throws when the OS is bound but its input was not supplied", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "a".repeat(64) },
      android: { date: null, sha256: null },
    };
    expect(() => assertBoundInputProvided(dates, "ios", false)).toThrow(/already bound/);
  });

  it("does not throw when the OS is bound and its input WAS supplied", () => {
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: "a".repeat(64) },
      android: { date: null, sha256: null },
    };
    expect(() => assertBoundInputProvided(dates, "ios", true)).not.toThrow();
  });

  it("does not throw when the OS isn't bound at all (nothing to recompute)", () => {
    expect(() => assertBoundInputProvided(BLANK, "ios", false)).not.toThrow();
    const dates: RecordedExportDates = {
      ios: { date: "2026-09-20", sha256: null },
      android: { date: null, sha256: null },
    };
    expect(() => assertBoundInputProvided(dates, "ios", false)).not.toThrow();
  });
});

describe("informationalBanner", () => {
  it("names the OS and says NOT THE RECORDED X1 RESULT", () => {
    expect(informationalBanner("ios")).toContain("NOT THE RECORDED X1 RESULT");
    expect(informationalBanner("ios")).toContain("iOS");
    expect(informationalBanner("android")).toContain("Android");
  });
});
