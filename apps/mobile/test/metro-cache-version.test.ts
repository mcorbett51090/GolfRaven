/**
 * MEDIUM (PR #39 gate): Metro's transform cache key ignores `EXPO_PUBLIC_*` VALUES, so a value inlined into a cached transform could ship again after the variable
 * changed or was unset, on every bundling path without `--clear` (`expo start`, Gradle, Xcode, `eas update`). `metro.config.js` folds a SHA-256 of Metro's own `cacheVersion`
 * and the sorted `EXPO_PUBLIC_*` NAME=value pairs into `config.cacheVersion`, which IS part of Metro's cache key. Run here as real child processes.
 *
 * The real-world experiment behind it (recorded in the README): `expo export --platform android --no-bytecode` with `EXPO_PUBLIC_STORE_URL=a`, then `=b`, WITHOUT `--clear` and
 * with a private TMPDIR: the second bundle contained `b` and no `a`; the same two runs with the `cacheVersion` line removed shipped `a` again.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const APP = fileURLToPath(new URL("..", import.meta.url));

function cacheVersion(env: Record<string, string>): string {
  const r = spawnSync(process.execPath, ["-e", `process.stdout.write(String(require("./metro.config.js").cacheVersion))`], {
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", ...env } as unknown as NodeJS.ProcessEnv,
    encoding: "utf8",
    cwd: APP,
  });
  if (r.status !== 0) throw new Error(`metro.config.js did not load: ${r.stderr}`);
  return r.stdout;
}

describe("metro.config.js cacheVersion", () => {
  it("is a SHA-256 hex digest", () => {
    expect(cacheVersion({})).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same EXPO_PUBLIC_* environment", () => {
    expect(cacheVersion({ EXPO_PUBLIC_X: "a" })).toBe(cacheVersion({ EXPO_PUBLIC_X: "a" }));
  });

  it("changes when an EXPO_PUBLIC_* VALUE changes (the property that matters: the value, not only the name)", () => {
    const a = cacheVersion({ EXPO_PUBLIC_STORE_URL: "https://a.example/alpha" });
    const b = cacheVersion({ EXPO_PUBLIC_STORE_URL: "https://b.example/beta" });
    expect(a).not.toBe(b);
    expect(a).not.toBe(cacheVersion({}));
  });

  it("changes when a variable is ADDED or REMOVED, and when a name changes with the same value", () => {
    const base = cacheVersion({ EXPO_PUBLIC_A: "1" });
    expect(cacheVersion({ EXPO_PUBLIC_A: "1", EXPO_PUBLIC_B: "2" })).not.toBe(base);
    expect(cacheVersion({})).not.toBe(base);
    expect(cacheVersion({ EXPO_PUBLIC_B: "1" })).not.toBe(base);
  });

  it("does not depend on the ORDER the variables were set in (the pairs are sorted)", () => {
    expect(cacheVersion({ EXPO_PUBLIC_A: "1", EXPO_PUBLIC_B: "2" })).toBe(cacheVersion({ EXPO_PUBLIC_B: "2", EXPO_PUBLIC_A: "1" }));
  });

  it("does NOT change for variables that are not EXPO_PUBLIC_* (a build-time secret elsewhere in the environment neither invalidates the cache nor enters the hash)", () => {
    const base = cacheVersion({ EXPO_PUBLIC_A: "1" });
    expect(cacheVersion({ EXPO_PUBLIC_A: "1", SOME_OTHER: "x", GOLFRAVEN_APP_ATTEST_ENV: "development" })).toBe(base);
  });

  it("NAME=value pairs cannot collide by moving a separator: A='1\\nB=2' differs from A='1', B='2'", () => {
    expect(cacheVersion({ EXPO_PUBLIC_A: "1\nEXPO_PUBLIC_B=2" })).not.toBe(cacheVersion({ EXPO_PUBLIC_A: "1", EXPO_PUBLIC_B: "2" }));
  });

  it("never prints a value: the digest is all the config exposes, and the source writes nothing about the pairs", () => {
    const v = cacheVersion({ EXPO_PUBLIC_STORE_URL: "https://secretish.example/very-unique-value" });
    expect(v).not.toContain("secretish");
    const src = readFileSync(`${APP}/metro.config.js`, "utf8");
    expect(src).toMatch(/config\.cacheVersion = publicEnvCacheVersion\(config\.cacheVersion, process\.env\)/);
    expect(src).toMatch(/createHash\("sha256"\)/);
  });
});
