#!/usr/bin/env node
/**
 * Post-export bundle scan: fails when a SECRET ended up inside the exported app (`expo export` output).
 *
 * `check-public-env.mjs` looks at the build ENVIRONMENT before bundling; this looks at the OUTPUT after it. The two can disagree: Metro's transform
 * cache key ignores `EXPO_PUBLIC_*` values, so a value inlined into an earlier export on the same machine can ship again even after the variable
 * was unset (the export scripts now pass `--clear`, and this scan is the backstop that does not depend on the cache behaving).
 *
 * It walks every file under the directory (JS bundles, Hermes bytecode, assets: read as bytes, so a string table is searched too) and reports:
 *   - `jwt_non_anon_role`: three base64url segments whose decoded payload is a JSON object with a `role` other than `anon` (a `service_role`
 *     or `authenticated` token);
 *   - `sb_secret_key`: a Supabase secret API key, `sb_secret_` followed by at least 16 key characters (`[A-Za-z0-9_-]`; a real key's body is ~30).
 *     The bare prefix is NOT a finding: the app's own parser contains the literal (`startsWith("sb_secret_")`, `src/config-values.ts`), so every
 *     export has it, and Hermes bytecode packs strings together, so the literal sits next to its neighbour (`sb_secret_shaped…`).
 * It prints the file (relative to the scanned directory) and the finding KIND, never the value.
 *
 * Usage: `node scripts/scan-bundle.mjs [dir]` (default `dist`). Exit codes: 0 clean, 1 a finding, 2 the scan could not run (missing or empty
 * directory, an unreadable file): an unscanned bundle is not a clean one.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SB_SECRET = /sb_secret_[A-Za-z0-9_-]{16,}/;
const JWT = /eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+/g;

/** The finding kinds in one file's bytes (a Set: one line per file and kind, however many times it occurs). */
export function scanText(text) {
  const kinds = new Set();
  if (SB_SECRET.test(text)) kinds.add("sb_secret_key");
  for (const m of text.matchAll(JWT)) {
    const payload = m[0].split(".")[1] ?? "";
    let claims;
    try {
      claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    } catch {
      continue; // not a JWT after all (three dotted identifiers in minified code)
    }
    if (claims !== null && typeof claims === "object" && "role" in claims && claims.role !== "anon") kinds.add("jwt_non_anon_role");
  }
  return kinds;
}

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else if (entry.isFile()) yield p;
  }
}

function main() {
  const dir = resolve(process.argv[2] ?? "dist");
  if (!statSync(dir).isDirectory()) throw new Error("not a directory");
  let files = 0;
  let findings = 0;
  for (const file of [...walk(dir)].sort()) {
    files += 1;
    // latin1 maps every byte to one character, so ASCII strings inside binary files (Hermes bytecode) are found as they are in text files.
    for (const kind of scanText(readFileSync(file).toString("latin1"))) {
      findings += 1;
      console.error(`scan-bundle: ${relative(dir, file)}: ${kind}. Value not shown.`);
    }
  }
  if (files === 0) throw new Error("no files to scan");
  if (findings > 0) {
    console.error(`scan-bundle: ${findings} finding(s). The export contains a secret: do NOT ship it. Rebuild with a clean environment and \`--clear\`.`);
    return 1;
  }
  console.log(`scan-bundle: ok (${files} files)`);
  return 0;
}

// `scanText` is exported for tests; the scan runs only when this file is the entry point.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    process.exit(main());
  } catch (e) {
    console.error(`scan-bundle: the scan could not run (${e instanceof Error ? e.message : "unknown error"}). Treating the export as unchecked.`);
    process.exit(2);
  }
}
