/**
 * LOW-D tripwire (PR #26 gate): on iOS the under-age flag lives in `golfraven.db`, which `expo-sqlite` 57.0.3 keeps
 * in `<Documents>/SQLite` — a directory iCloud / iTunes backups include. There is NO way, in the packages installed
 * today, to set `NSURLIsExcludedFromBackupKey` from JS, so nothing is implemented here (adding a native module is
 * P4.2's call, not this slice's). This test pins the facts that conclusion rests on, read from the installed
 * packages' own source, so an upgrade that ADDS an exclusion option fails here and tells you to use it.
 * It checks source text, not device behaviour `[unverified — never run on a device]`.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const requireHere = createRequire(import.meta.url);
const pkgDir = (name: string, from = requireHere): string => dirname(from.resolve(`${name}/package.json`));
const sqliteDir = pkgDir("expo-sqlite");
// `expo-file-system` is a dependency of `expo`, not of this app: resolve it THROUGH expo.
const fileSystemDir = pkgDir("expo-file-system", createRequire(requireHere.resolve("expo/package.json")));

function sourceFiles(dir: string, exts: readonly string[]): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "build" || name === "vendor" || name.endsWith(".xcframework")) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sourceFiles(p, exts));
    else if (exts.some((e) => name.endsWith(e))) out.push(p);
  }
  return out;
}
const mentions = (dir: string, re: RegExp): string[] =>
  ["ios", "android/src", "src"].flatMap((d) => sourceFiles(join(dir, d), [".swift", ".kt", ".ts", ".tsx", ".m", ".mm"])).filter((f) => re.test(readFileSync(f, "utf8")));

describe("iOS backup exclusion of golfraven.db (open: P4.2)", () => {
  it("the scan is not vacuous: it sees the packages' native and TypeScript sources", () => {
    expect(sourceFiles(join(sqliteDir, "ios"), [".swift"]).length).toBeGreaterThan(3);
    expect(sourceFiles(join(sqliteDir, "src"), [".ts"]).length).toBeGreaterThan(3);
    expect(sourceFiles(join(fileSystemDir, "ios"), [".swift"]).length).toBeGreaterThan(5);
    expect(sourceFiles(join(fileSystemDir, "src"), [".ts"]).length).toBeGreaterThan(3);
  });

  it("expo-sqlite's default directory on iOS is <Documents>/SQLite (backed up), and `directory` is the only placement option", () => {
    const swift = readFileSync(join(sqliteDir, "ios", "SQLiteModule.swift"), "utf8");
    expect(swift).toMatch(/documentDirectory\?\.appendingPathComponent\("SQLite"\)/);
    expect(readFileSync(join(sqliteDir, "build", "SQLiteDatabase.d.ts"), "utf8")).toMatch(/openDatabaseAsync\(databaseName: string, options\?: SQLiteOpenOptions, directory\?: string\)/);
  });

  it("neither expo-sqlite nor expo-file-system exposes NSURLIsExcludedFromBackupKey (if this fails, an option now exists: use it and delete this test)", () => {
    const re = /ExcludedFromBackup|isExcludedFromBackup|NSURLIsExcluded/i;
    expect(mentions(sqliteDir, re)).toEqual([]);
    expect(mentions(fileSystemDir, re)).toEqual([]);
  });
});
