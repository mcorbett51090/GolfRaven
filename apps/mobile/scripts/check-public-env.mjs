#!/usr/bin/env node
/**
 * Export-time guard: refuses to build when a SECRET key is in an `EXPO_PUBLIC_*` variable.
 *
 * Metro inlines the raw value of every `EXPO_PUBLIC_*` variable into the JavaScript bundle, so a `service_role` JWT or an `sb_secret_…` key placed
 * there would ship to every device. The app's runtime parser (`parseSupabaseAnonKey`) only makes the app ignore such a key, after it is already in
 * the bundle. This script runs the SAME parser (`src/config-values.ts`, via `findPublicEnvProblems`) over the build's environment BEFORE bundling,
 * and exits 1 on a problem. It prints the variable NAME and the reason, never the value.
 *
 * What it reads: `process.env`, and the `.env*` files Expo CLI loads for this project (`.env`, `.env.local`, `.env.<mode>`, `.env.<mode>.local`).
 * Run by `pnpm export:ios`, `pnpm export:android`, and EAS Build's `eas-build-pre-install` hook (package.json). `npx expo export` called directly
 * does not run it: use the scripts above.
 *
 * `--root <dir>`: the project directory to read `.env*` files from (default: the app directory). Exit codes: 0 clean, 1 problem found.
 */
import { readdirSync, readFileSync } from "node:fs";
import { registerHooks } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Node notes that the .ts files have no package "type"; the note is noise here (a build log should show only real problems).
process.removeAllListeners("warning");

// The app's sources import each other without extensions (Metro/TypeScript style); let plain Node resolve them to `.ts` (type stripping).
registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (e) {
      if (specifier.startsWith(".") && e && e.code === "ERR_MODULE_NOT_FOUND") return nextResolve(`${specifier}.ts`, context);
      throw e;
    }
  },
});

const here = dirname(fileURLToPath(import.meta.url));
const { findPublicEnvProblems } = await import(new URL("../src/config-values.ts", import.meta.url).href);

const rootFlag = process.argv.indexOf("--root");
const root = resolve(rootFlag >= 0 ? (process.argv[rootFlag + 1] ?? "") : join(here, ".."));

/** KEY=VALUE lines (optionally `export `-prefixed, optionally quoted); `#` comments and blanks skipped. Enough for what Expo's dotenv accepts here. */
function parseDotenv(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m || m[1] === undefined) continue;
    let v = m[2] ?? "";
    const q = v[0];
    if ((q === '"' || q === "'") && v.endsWith(q) && v.length >= 2) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, "");
    out[m[1]] = v;
  }
  return out;
}

const sources = [{ label: "process.env", env: process.env }];
let files = [];
try {
  files = readdirSync(root).filter((f) => /^\.env(\.[A-Za-z0-9_-]+)*$/.test(f));
} catch {
  // no such directory: only process.env is checked
}
for (const f of files.sort()) {
  try {
    sources.push({ label: f, env: parseDotenv(readFileSync(join(root, f), "utf8")) });
  } catch {
    // unreadable file: Expo would not load it either
  }
}

let bad = 0;
for (const { label, env } of sources) {
  for (const p of findPublicEnvProblems(env)) {
    bad += 1;
    const why = p.problem === "secret_shaped" ? "looks like a SECRET key (service_role / sb_secret_), which Metro would inline into the app bundle" : "is not a usable public Supabase key (it must be the anon JWT or an sb_publishable_ key)";
    console.error(`check-public-env: ${p.name} (${label}) ${why}. Value not shown.`);
  }
}
if (bad > 0) {
  console.error(`check-public-env: ${bad} problem(s). Refusing to export: put only PUBLIC values in EXPO_PUBLIC_* variables.`);
  process.exit(1);
}
console.log("check-public-env: ok");
