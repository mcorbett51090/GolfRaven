// Metro configuration. Two jobs:
//  1. the stock Expo defaults (`expo/metro-config`), unchanged;
//  2. run the public-env guard (`scripts/check-public-env.mjs`) every time Metro is configured, so EVERY path that bundles the app runs it:
//     `expo start`, `expo export`, `expo run:*`, `eas update`, and the Gradle / Xcode build phases (they all start Metro, which loads this file).
//     Metro inlines the raw value of every `EXPO_PUBLIC_*` variable into the bundle, so a `service_role` JWT or `sb_secret_...` key in one would
//     ship to every device. The guard prints only the variable NAME and reason, never the value, and exits 1 on a problem: this file then throws
//     and the bundle is not produced. With no `EXPO_PUBLIC_*` secrets (the normal local case, including no environment at all) it is silent.
//     The explicit `check:public-env` / `export:*` scripts and EAS's pre-install hook remain: the guard is cheap and a second line is fine.
//  A guard that cannot RUN (exit code other than 0 or 1: an old Node without type stripping, a missing file) is reported as a warning and does not
//  block the bundle: refusing every build because a checker is broken would only teach people to remove it. Only a real finding blocks.
const { getDefaultConfig } = require("expo/metro-config");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

function runPublicEnvGuard() {
  const script = path.join(__dirname, "scripts", "check-public-env.mjs");
  const r = spawnSync(process.execPath, [script], { encoding: "utf8", env: process.env, stdio: ["ignore", "pipe", "pipe"] });
  if (r.status === 1) {
    process.stderr.write(r.stderr);
    throw new Error("metro.config.js: refusing to bundle: a secret-shaped value is in an EXPO_PUBLIC_* variable (named above; value not shown).");
  }
  if (r.status !== 0) {
    process.stderr.write(`metro.config.js: warning: the public-env guard could not run (exit ${String(r.status)}${r.error ? `, ${r.error.message}` : ""}); the bundle was NOT checked.\n`);
  }
}

runPublicEnvGuard();

module.exports = getDefaultConfig(__dirname);
