/**
 * LOW-D tripwire (PR #26 gate), updated for P4.2a: `golfraven.db` is in `<Documents>/SQLite` on iOS (`expo-sqlite` 57.0.3), a directory iCloud /
 * iTunes backups include, and there is NO way, in the packages installed today, to set `NSURLIsExcludedFromBackupKey` from JS. That is why the
 * O18 under-age flag no longer lives there: it is a `…ThisDeviceOnly` Keychain item (`expo-secure-store`, `test/secure-storage.test.ts`), so it is
 * excluded from backups and device migration. What stays in the backed-up database is the catalog cache and the evidence outbox (a player's own
 * pending plays: personal data in an iCloud backup the player controls; closing that needs the native exclusion below, still open).
 * This test pins (1) the facts the "cannot exclude the DB from JS" conclusion rests on, read from the installed packages' own source, so an upgrade
 * that ADDS an exclusion option fails here and tells you to use it, and (2) that the gate is wired to the secure store, not to SQLite.
 * It checks source text, not device behaviour `[unverified: never run on a device]`.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const requireHere = createRequire(import.meta.url);
const pkgDir = (name: string, from = requireHere): string => dirname(from.resolve(`${name}/package.json`));
const sqliteDir = pkgDir("expo-sqlite");
// `expo-file-system` (57.0.7) is a dependency of `expo` and, since P4.2a, of this app too (the share sheet): resolve it THROUGH expo, the same copy.
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

describe("iOS backup exclusion of golfraven.db (the age flag is out of it; the DB itself is still open)", () => {
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

describe("the under-age flag is not in the backed-up database", () => {
  const services = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../src/runtime/services.ts"), "utf8");

  it("the age gate is built over the secure-store flags (or the fail-closed store), never over the SQLite `flags`", () => {
    expect(services).toMatch(/new AgeGate\(ageFlags\)/);
    expect(services).not.toMatch(/new AgeGate\(flags\)/);
    expect(services).toMatch(/new SecureDeviceFlagStore\(secure\)/);
    expect(services).toMatch(/failClosedAgeFlags\(\)/);
    expect(services).toMatch(/migrateAgeFlag\(flags, secureFlags\)/);
  });
});
