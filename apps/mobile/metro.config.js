// Metro configuration. Three jobs:
//  1. the stock Expo defaults (`expo/metro-config`), unchanged except for (3);
//  2. run the public-env guard (`scripts/check-public-env.mjs`) every time Metro is configured, so EVERY path that bundles the app runs it:
//     `expo start`, `expo export`, `expo run:*`, `eas update`, and the Gradle / Xcode build phases (they all start Metro, which loads this file).
//     Metro inlines the raw value of every `EXPO_PUBLIC_*` variable into the bundle, so a `service_role` JWT or `sb_secret_...` key in one would
//     ship to every device. The guard prints only the variable NAME and reason, never the value, and exits 1 on a problem: this file then throws
//     and the bundle is not produced. With no `EXPO_PUBLIC_*` secrets (the normal local case, including no environment at all) it is silent.
//     The explicit `check:public-env` / `export:*` scripts and EAS's pre-install hook remain: the guard is cheap and a second line is fine.
//  The guard's exit codes mean different things and are reported as such: 1 is a REAL finding ("secret-shaped value"); 2 (or anything else: a
//  signal, a spawn failure) is "the guard could not run" (an old Node without type stripping, a missing file, the parser failing to load). Both
//  BLOCK the bundle: fail closed. An unchecked bundle is exactly what the guard exists to prevent, and a warning in a long build log is not read.
//  The two throw different messages so a broken checker is never mistaken for a leaked key (or the reverse).
//  3. `cacheVersion` = a SHA-256 over Metro's own version and the sorted `EXPO_PUBLIC_*` NAME=value pairs (`publicEnvCacheVersion`), so EVERY bundling path invalidates its transform cache
//     when a public value changes, not only the `--clear` of `pnpm export:*` (`test/metro-cache-version.test.ts`, and the README's experiment).
const { getDefaultConfig } = require("expo/metro-config");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function runPublicEnvGuard() {
  const script = path.join(__dirname, "scripts", "check-public-env.mjs");
  // A missing guard must say so honestly: spawning a missing script makes Node exit 1 with its own "Cannot find module" text, which the check below would then read as a
  // FINDING ("a secret-shaped value"). Fail closed, with the right message.
  if (!fs.existsSync(script)) {
    throw new Error(`metro.config.js: refusing to bundle: the env guard could not run (${script} does not exist), so the environment was NOT checked. This is a broken checkout, not a finding: restore scripts/check-public-env.mjs.`);
  }
  const r = spawnSync(process.execPath, [script], { encoding: "utf8", env: process.env, stdio: ["ignore", "pipe", "pipe"] });
  if (r.status === 1) {
    process.stderr.write(r.stderr);
    throw new Error("metro.config.js: refusing to bundle: a secret-shaped value is in an EXPO_PUBLIC_* variable (named above; value not shown).");
  }
  if (r.status !== 0) {
    if (r.stderr) process.stderr.write(r.stderr);
    throw new Error(`metro.config.js: refusing to bundle: the env guard could not run (exit ${String(r.status)}${r.error ? `, ${r.error.message}` : ""}), so the environment was NOT checked. This is a broken checker, not a finding: fix or restore scripts/check-public-env.mjs.`);
  }
}

runPublicEnvGuard();

/** A cache version that changes whenever any `EXPO_PUBLIC_*` name or value does. Metro inlines the raw value of every `EXPO_PUBLIC_*` variable into the transformed module
 * (Expo's Babel preset), but its transform cache key does not include the VALUES: a value inlined into a cached transform could ship again after the variable changed or was
 * unset, on any bundling path that does not pass `--clear` (`expo start`, Gradle, Xcode, `eas update`). `cacheVersion` is part of Metro's cache key, so folding a SHA-256 of the sorted
 * `NAME=value` pairs into it invalidates the cache exactly when a public value changes. The hash is one-way and is never printed. Takes the base version so Metro's own is kept. */
function publicEnvCacheVersion(baseVersion, env) {
  const pairs = Object.keys(env)
    .filter((name) => name.startsWith("EXPO_PUBLIC_"))
    .sort()
    .map((name) => [name, String(env[name])]);
  // JSON, not a joined string: a value that contains a newline and `NAME=` cannot be made to look like two variables.
  return crypto.createHash("sha256").update(JSON.stringify([String(baseVersion), pairs])).digest("hex");
}

const config = getDefaultConfig(__dirname);
config.cacheVersion = publicEnvCacheVersion(config.cacheVersion, process.env);

module.exports = config;
